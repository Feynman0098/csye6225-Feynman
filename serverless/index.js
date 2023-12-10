const axios = require('axios');
const { Storage } = require('@google-cloud/storage');
const AWS = require('aws-sdk');
const ses = new AWS.SES();
const dynamoDB = new AWS.DynamoDB.DocumentClient();
exports.handler = async function (event) {

    const snsMessage = event.Records[0].Sns.Message;
    console.log("Received SNS message:", snsMessage);

    const lines = snsMessage.split('\n');
    const emailLine = lines.find(line => line.startsWith("User Email: "));
    const urlLine = lines.find(line => line.startsWith("URL: "));
    const assignmentIdLine = lines.find(line => line.startsWith("AssignmentId: "));
    const attemptNumLine = lines.find(line => line.startsWith("Attempt Num: "));

    const email = emailLine.replace("User Email: ", "").trim();
    const url = urlLine.replace("URL: ", "").trim();
    const assignmentId = assignmentIdLine.replace("AssignmentId: ", "").trim();
    const attemptNum = attemptNumLine.replace("Attempt Num: ", "").trim();

    
    // download and save
    const bucketName = process.env.BUCKET_NAME;
    const jsonString = process.env.JSON_STRING;
    const tableName = process.env.TABLE_NAME;
    console.log("tableName");
    console.log(tableName);
    const jsonObject = JSON.parse(jsonString);
    // const storage = new Storage({ credentials: {
    //   private_key: jsonString,
    //   client_email: clientEmail,
    // }, });
    const storage = new Storage({ credentials: jsonObject });

    // bucket
    const bucket = storage.bucket(bucketName);
    try {
        const [files] = await bucket.getFiles();
    } catch (err) {
        console.error('cant access bucket:', err);
        return;
    }

    const storeKey = email + "-" + assignmentId + "-" + attemptNum;
    
    try {
        // download file
        const response = await axios({
            method: 'GET',
            url: url,
            responseType: 'stream'
        });
        const parts = urlLine.split('/');
        const filename = parts[parts.length - 1];
        const blob = bucket.file(filename);
        const blobStream = blob.createWriteStream()
        // send success notification
        const sourceEmail = process.env.SOURCE_EMAIL;
        const text = process.env.EMAIL_TEXT_SUCCESS;
        sendEmail(sourceEmail, email, text, storeKey, tableName);

        // upload to GCP
        response.data.pipe(blobStream);

        await new Promise((resolve, reject) => {
            blobStream.on('finish', () => {
                resolve("upload success");
            });

            blobStream.on('error', err => {
                console.error('upload failed:', err);
                reject(err);
            });
        });
    } catch (error) {
        // send fail notification
        const sourceEmail = process.env.SOURCE_EMAIL;
        const text = process.env.EMAIL_TEXT_FAIL;
        
        sendEmail(sourceEmail, email, text, storeKey, tableName);

        console.error('error in processing...:', error);
        throw new Error('fail');
    }
    
  // TODO implement
  const response = {
    statusCode: 200,
    body: JSON.stringify('Hello from Lambda!'),
  };
  return response;
};

async function sendEmail(source, recipient, bodyText, storeKey, tableName) {
    const params = {
        Source: source,
        Destination: {
            ToAddresses: [recipient]
        },
        Message: {
            Subject: {
                Data: process.env.EMAIL_SUBJECT
            },
            Body: {
                Text: {
                    Data: bodyText
                }
            }
        }
    };

    try {
        await ses.sendEmail(params).promise();
        console.log('Email sent successfully');
        // save to DB
        const paramsToStore = {
            TableName: tableName,
            Item: {
                'Id': storeKey,
                'Recipient': recipient,
                'Message': params.Message,
                'Timestamp': new Date().toISOString()
            }
        };
        try {
            await dynamoDB.put(paramsToStore).promise();
            console.log('Email info saved to DynamoDB');
        } catch (error) {
            console.error('Error saving email info to DynamoDB:', error);
        }
        return true;
    } catch (error) {
        console.error('Email sending failed:', error);
        return false;
    }
};

