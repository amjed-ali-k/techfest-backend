import { Hono } from "hono";
import { cors } from 'hono/cors'

interface Env {
  GOOGLE_CLIENT_EMAIL: string;
  GOOGLE_PRIVATE_KEY: string;
}

const app = new Hono<{ Bindings: Env }>();
app.use('*', cors())
app.get("/", (c) => {
  return c.text("Hello Hono!");
});

// Define request body type
interface FormRequest {
  formId: string;
}

// Define response types
interface FormResponse {
  formId: string;
  responseCount: number;
}

interface ErrorResponse {
  error: string;
}

// POST endpoint to get the response count
app.get('/form-responses/:formId', async (c) => {
  try {
    // Parse the request body with type assertion
    const formId =  c.req.param('formId')
    if (!formId) {
      return c.json<ErrorResponse>({ error: 'Form ID is required' }, 400);
    }

    // Get the Google auth token
    const token = await getGoogleAuthToken(c.env.GOOGLE_CLIENT_EMAIL, c.env.GOOGLE_PRIVATE_KEY);
    // Fetch the form response count
    const responseCount = await getFormResponseCount(formId, token);

    // Return the response
    return c.json<FormResponse>({ formId, responseCount }, 200);
  } catch (error) {
    return c.json<ErrorResponse>({ error: (error as Error).message }, 500);
  }
});

// Function to get Google OAuth token
async function getGoogleAuthToken(clientEmail: string, privateKey: string): Promise<string> {
  const scope = 'https://www.googleapis.com/auth/forms.responses.readonly';

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientEmail,
    scope,
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600, // Token expires in 1 hour
    iat: now,
  };

  const header = { alg: 'RS256', typ: 'JWT' };
  const base64Header = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const base64Payload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const unsignedToken = `${base64Header}.${base64Payload}`;

  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(privateKey),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(unsignedToken)
  );
  const base64Signature = arrayBufferToBase64(signature);
  const jwt = `${unsignedToken}.${base64Signature}`;

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  const data = (await response.json()) as { access_token: string; error_description?: string };
  if (!response.ok) throw new Error(data.error_description || 'Authentication failed');
  return data.access_token;
}

// Function to fetch the response count for a form
async function getFormResponseCount(formId: string, token: string): Promise<number> {
  const response = await fetch(`https://forms.googleapis.com/v1/forms/${formId}/responses`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  const data = (await response.json()) as { responses?: unknown[]; error?: { message: string } };
  if (!response.ok) throw new Error(data.error?.message || 'Failed to fetch responses');

  // Count the responses array length, default to 0 if undefined
  return data.responses ? data.responses.length : 0;
}

// Helper functions
function pemToArrayBuffer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----|\n/g, '');
  const binary = atob(b64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buffer[i] = binary.charCodeAt(i);
  return buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export default app;
