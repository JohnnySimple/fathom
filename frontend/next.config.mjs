/** @type {import('next').NextConfig} */
const nextConfig = {
  // The API runs as a separate process on :8000. Proxying through Next keeps
  // the browser on one origin, so there are no CORS preflights in development
  // and the deployed setup can put both behind one host unchanged.
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.FATHOM_API_URL ?? "http://127.0.0.1:8000"}/api/:path*`,
      },
    ];
  },
  devIndicators: false
};
export default nextConfig;
