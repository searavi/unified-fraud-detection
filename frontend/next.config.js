/** @type {import('next').NextConfig} */

const backend = process.env.BACKEND_URL ?? "http://localhost:4000"

const nextConfig = {
    async rewrites() {
        return [
            {
                source: '/api/:path*',
                destination: `${backend}/:path*`,
            },
            // /auth/* (login, callback, logout, status) is called bare, no /api prefix, by
            // Navbar/flagged pages and the OAuth provider's own redirect back to /auth/callback
            // — without this, those fetches/navigations hit Next's own 404 instead of the
            // backend, and login state silently always resolves to "not available".
            {
                source: '/auth/:path*',
                destination: `${backend}/auth/:path*`,
            },
        ]
    },
}

module.exports = nextConfig
