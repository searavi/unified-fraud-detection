/** @type {import('next').NextConfig} */

const backend = process.env.BACKEND_URL ?? "http://localhost:4000"

const nextConfig = {
    async rewrites() {
        return [
            {
                source: '/api/:path*',
                destination: `${backend}/:path*`,
            },
        ]
    },
}

module.exports = nextConfig
