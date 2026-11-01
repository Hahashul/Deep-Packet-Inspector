const dev = process.env.NODE_ENV !== "production";
const BACKEND = process.env.BACKEND_URL || "http://127.0.0.1:8000";

/** @type {import('next').NextConfig} */
const config = {
  // production: static export into out/, served by FastAPI (one command, one URL)
  ...(dev ? {} : { output: "export", trailingSlash: true }),
  images: { unoptimized: true },
  // dev only: proxy the API and websocket to FastAPI
  ...(dev
    ? {
        async rewrites() {
          return [
            { source: "/api/:path*", destination: `${BACKEND}/api/:path*` },
            { source: "/ws", destination: `${BACKEND}/ws` },
          ];
        },
      }
    : {}),
};
export default config;
