// functions/virustotal-proxy.js

const fetch = require('node-fetch');
const FormData = require('form-data');
const busboy = require('busboy');

// Funzione helper per parsare il form con busboy, che è asincrono
function parseMultipartForm(event) {
    return new Promise((resolve) => {
        const fields = {};
        const files = {};

        const bb = busboy({
            headers: {
                'content-type': event.headers['content-type'] || event.headers['Content-Type']
            }
        });

        bb.on('file', (name, stream, info) => {
            const { filename, encoding, mimeType } = info;
            const chunks = [];
            stream.on('data', (chunk) => {
                chunks.push(chunk);
            });
            stream.on('end', () => {
                files[name] = {
                    filename,
                    content: Buffer.concat(chunks),
                    contentType: mimeType,
                    encoding,
                };
            });
        });

        bb.on('field', (name, value) => {
            fields[name] = value;
        });

        bb.on('close', () => {
            resolve({ fields, files });
        });

        bb.end(Buffer.from(event.body, 'base64'));
    });
}


exports.handler = async function(event) {
    const baseUrl = 'https://www.virustotal.com/api/v3';

    try {
        const contentType = event.headers['content-type'] || event.headers['Content-Type'];

        if (contentType && contentType.startsWith('multipart/form-data')) {
            // --- GESTIONE FILE CON BUSBOY ---
            const { fields, files } = await parseMultipartForm(event);
            const apiKey = fields.apiKey;
            const file = files.file;
            
            if (!apiKey || !file) {
                 return { statusCode: 400, body: JSON.stringify({ error: 'Dati del form (file o API key) non ricevuti correttamente.' }) };
            }

            const uploadUrl = `${baseUrl}/files`;
            
            const serverFormData = new FormData();
            serverFormData.append('file', file.content, file.filename);

            const response = await fetch(uploadUrl, {
                method: 'POST',
                headers: {
                    ...serverFormData.getHeaders(),
                    'x-apikey': apiKey
                },
                body: serverFormData
            });
            const data = await response.json();
            return { statusCode: response.status, body: JSON.stringify(data) };

        } else {
            // --- GESTIONE URL (invariata) ---
            const { apiKey, endpoint, options } = JSON.parse(event.body);
            if (!apiKey || !endpoint) {
                return { statusCode: 400, body: JSON.stringify({ error: 'API key o endpoint mancanti' }) };
            }
            const url = `${baseUrl}/${endpoint}`;
            const fetchOptions = { ...options, headers: { ...(options.headers || {}), 'x-apikey': apiKey } };
            const response = await fetch(url, fetchOptions);
            const data = await response.json();
            return { statusCode: response.status, body: JSON.stringify(data) };
        }
    } catch (error) {
        console.error('Crash nella funzione proxy:', error);
        return { statusCode: 500, body: JSON.stringify({ error: 'Errore interno critico del server', details: error.message }) };
    }
};
