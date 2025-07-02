const multipart = require('aws-lambda-multipart-parser');

exports.handler = async function(event) {
    console.log("--- FUNZIONE DI DEBUG ATTIVATA ---");
    console.log("HEADER RICEVUTI:", event.headers);
    console.log("IL BODY È CODIFICATO IN BASE64:", event.isBase64Encoded);

    try {
        const form = await multipart.parse(event);
        console.log("RISULTATO DEL PARSING DEL FORM:", form);

        // Crea un report di quello che abbiamo trovato
        const report = {
            apiKeyTrovata: !!form.apiKey,
            chiaveApi: form.apiKey || "Non trovata",
            numeroFileTrovati: form.files ? form.files.length : 0,
            datiCompletiDelForm: form
        };

        // Restituisci sempre successo per poter vedere il report nel browser
        return {
            statusCode: 200, 
            body: JSON.stringify(report)
        };

    } catch (error) {
        console.error('CRASH DURANTE IL PARSING:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({
                error: 'La funzione è andata in crash durante il parsing del form.',
                details: error.message
            })
        };
    }
};
