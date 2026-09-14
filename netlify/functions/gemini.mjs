// Netlify entry point: reuses the Vercel handler in api/gemini.js.
import { POST } from '../../api/gemini.js';

export default POST;
export const config = { path: '/api/gemini' };
