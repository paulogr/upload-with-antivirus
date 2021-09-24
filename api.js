const fs = require('fs')
const path = require('path')
const crypto = require("crypto")
const util = require('util')
const stream = require('stream')
const pump = util.promisify(stream.pipeline)
const got = require('got')
const admin = require('firebase-admin')

const Sensible = require('fastify-sensible')
const Multipart = require('fastify-multipart')

/** @type import('fastify').FastifyPluginAsync */
async function api (server, opts) {
  const serviceAccount = {
    type: 'service_account',
    project_id: process.env.GCP_PROJECT_ID,
    private_key_id: process.env.GCP_PRIVATE_KEY_ID,
    private_key: process.env.GCP_PRIVATE_KEY,
    client_email: process.env.GCP_CLIENT_EMAIL,
    client_id: process.env.GCP_CLIENT_ID,
    auth_uri: process.env.GCP_AUTH_URI,
    token_uri: process.env.GCP_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.GCP_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.GCP_CLIENT_X509_CERT_URL
  }

  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) })

  const bucket = admin.storage().bucket('bitrust-register-files')

  server.register(Sensible)
  server.register(Multipart, {
    limits: {
      fieldNameSize: 1,
      fieldSize: 0,
      fields: 0,
      fileSize: 10485760,  // 10 MB
      files: 20,
      headerPairs: 50
    }
  })

  const FILENAMES = {
    admdoc1: 'adm-contrato-social',
    admdoc2: 'adm-demonstracao-contabil',
    admdoc3: 'adm-documento-identidade-empresario',
    admdoc4: 'adm-documento-identidade-administrador',
    admdoc5: 'adm-procuracao-operador',
    repdoc1: 'rep-documento-cpf',
    repdoc2: 'rep-documento-rg',
    repdoc3: 'rep-comprovante-endereco',
  }

  const FIELDNAMES = Object.keys(FILENAMES)

  const MIMETYPES = [
    'image/jpeg ',
    'image/png',
    'application/pdf '
  ]

  server.route({
    path: '/register/:contactId/upload',
    method: 'POST',
    async handler (req, reply) {
      const { contactId } = req.params
      const files = await req.saveRequestFiles()

      const unknowField = files.some(f => !FIELDNAMES.includes(f.fieldname))

      if (unknowField) {
        reply.badRequest('Unknow field')
        return
      }

      const unknowType = files.some(f => !MIMETYPES.includes(f.mimetype))

      if (unknowType) {
        reply.badRequest('Unknow file type')
        return
      }

      for await (const file of files) {
        const hash = crypto.createHash('sha256').setEncoding('hex')
        await pump(fs.createReadStream(file.filepath), hash)
        file.sha256 = hash.read()
      }

      const results = await Promise.all(
        files.map(f => got({ url: `https://www.virustotal.com/api/v3/files/${f.sha256}`, headers: { 'x-apikey': '6c139acf63d6451203194339f94d38a9683c5a679a81464adf637dd974bad54d' }, throwHttpErrors: false, responseType: 'json' }))
      )

      const foundFiles = results.filter(r => r.statusCode === 200)
      const virusDetected = foundFiles.some(ff => ff.body.data.attributes.last_analysis_stats.malicious > 1)

      if (virusDetected) {
        reply.badRequest('Virus detected')
        return
      }

      let indexFile = 1

      for await (const file of files) {
        const bucketFile = bucket.file(`${contactId}/${`${indexFile}`.padStart(2, '0')}-${FILENAMES[file.fieldname]}${path.extname(file.filename)}`)
        await pump(fs.createReadStream(file.filepath), bucketFile.createWriteStream())

        indexFile++
      }

      return { ok: true, timestamp: new Date().toISOString() }
    }
  })
}

module.exports = api
