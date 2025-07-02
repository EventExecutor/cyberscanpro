const fetch = require('node-fetch');
const multipart = require('aws-lambda-multipart-parser');
const FormData = require('form-data');

exports.handler = async function(event) {
    const baseUrl = 'https://www.virustotal.com/api/v3';

    try {
        const contentType = event.headers['content-type'] || event.headers['Content-Type'];

        if (contentType && contentType.startsWith('multipart/form-data')) {
            const form = await multipart.parse(event);
            const apiKey = form.apiKey;

            // ========= LA CORREZIONE È QUI =========
            // Aggiungiamo un controllo per assicurarci che il file sia stato ricevuto
            if (!apiKey || !form.files || form.files.length === 0) {
                console.error("Errore: API key o file mancanti nel form ricevuto.", { apiKey: !!apiKey, files: form.files });
                return { statusCode: 400, body: JSON.stringify({ error: 'Dati del form (file o API key) incompleti o corrotti.' }) };
            }

            const file = form.files[0];
            // =======================================

            const uploadUrl = `${baseUrl}/files`;

            const formData = new FormData();
            formData.append('file', file.content, file.filename);

            const response = await fetch(uploadUrl, {
                method: 'POST',
                headers: {
                    ...formData.getHeaders(),
                    'x-apikey': apiKey
                },
                body: formData
            });

            const data = await response.json();
            return { statusCode: response.status, body: JSON.stringify(data) };

        } else {
            // --- GESTIONE URL (invariata e funzionante) ---
            if (event.httpMethod !== 'POST') {
                return { statusCode: 405, body: 'Method Not Allowed' };
            }
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
        console.error('Errore nella funzione proxy:', error);
        return { statusCode: 500, body: JSON.stringify({ error: 'Errore interno del server proxy', details: error.message }) };
    }
};
