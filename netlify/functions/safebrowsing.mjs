// Netlify entry point: reuses the Vercel handler in api/safebrowsing.js.
import { POST } from '../../api/safebrowsing.js';

export default POST;
export const config = { path: '/api/safebrowsing' };
