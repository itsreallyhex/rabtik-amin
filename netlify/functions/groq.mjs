// Netlify entry point: reuses the Vercel handler in api/groq.js.
import { POST } from '../../api/groq.js';

export default POST;
export const config = { path: '/api/groq' };
