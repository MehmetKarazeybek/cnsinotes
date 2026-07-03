const crypto = require('crypto');
const SECRET = process.env.JWT_SECRET || 'varsayilan-gizli-anahtar';

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Sadece POST' });

  try {
    const { license } = req.body;
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '0.0.0.0';

    const match = /^ZEYX-(\d{6})-OK$/.exec(license);
    if (!match || (parseInt(match[1], 10) % 97) !== 43) {
      return res.status(403).json({ error: 'Gecersiz anahtar' });
    }

    const timestamp = Date.now();
    const payload = `${clientIP}:${license}:${timestamp}`;
    const signature = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    const token = `${Buffer.from(clientIP).toString('base64')}.${timestamp}.${signature}`;

    return res.status(200).json({ success: true, token, ip: clientIP });
  } catch (err) {
    return res.status(500).json({ error: 'Sunucu hatasi' });
  }
};
