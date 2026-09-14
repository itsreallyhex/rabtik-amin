// Netlify entry point: reuses the Vercel handler in api/virustotal.js.
import { POST } from '../../api/virustotal.js';

export default POST;
export const config = { path: '/api/virustotal' };
