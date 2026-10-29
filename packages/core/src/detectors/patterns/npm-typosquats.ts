// ─────────────────────────────────────────────────────────────────────────────
// npm typosquat data
//
// KNOWN_TYPOSQUATS: names that were published as malware imitating a popular
// package (most from the 2017 "hacktask" batch that stole environment variables on
// install, removed by npm and now held as security placeholders). Depending on one
// is a mistake whatever version it resolves to.
//
// POPULAR_PACKAGES: well-known unscoped names used for a conservative
// edit-distance-1 check (see npmTyposquatTarget). LEGITIMATE_NEIGHBOURS lists real,
// widely used packages that happen to sit one edit away from a popular name.
// ─────────────────────────────────────────────────────────────────────────────

/** Known malicious typosquat -> the package it imitated. */
export const KNOWN_TYPOSQUATS: Readonly<Record<string, string>> = {
  crossenv: "cross-env",
  "cross-env.js": "cross-env",
  babelcli: "babel-cli",
  "d3.js": "d3",
  "fabric-js": "fabric",
  ffmepg: "ffmpeg",
  gruntcli: "grunt-cli",
  "http-proxy.js": "http-proxy",
  "jquery.js": "jquery",
  mongose: "mongoose",
  "mssql.js": "mssql",
  "mssql-node": "mssql",
  mysqljs: "mysql",
  nodecaffe: "caffe",
  nodefabric: "fabric",
  "node-fabric": "fabric",
  nodeffmpeg: "ffmpeg",
  "nodemailer-js": "nodemailer",
  "nodemailer.js": "nodemailer",
  nodemssql: "mssql",
  noderequest: "request",
  nodesass: "node-sass",
  nodesqlite: "sqlite3",
  "node-opensl": "openssl",
  "node-openssl": "openssl",
  "opencv.js": "opencv",
  "openssl.js": "openssl",
  "sqlite.js": "sqlite3",
  sqliter: "sqlite3",
  "discordi.js": "discord.js",
  electorn: "electron",
  loadyaml: "js-yaml",
};

/** Popular unscoped npm packages used as edit-distance targets. */
export const POPULAR_PACKAGES: readonly string[] = [
  // frameworks and UI
  "react",
  "react-dom",
  "react-router",
  "react-router-dom",
  "react-redux",
  "react-hook-form",
  "react-icons",
  "react-query",
  "next",
  "next-auth",
  "nuxt",
  "vue",
  "vue-router",
  "svelte",
  "angular",
  "redux",
  "zustand",
  "jotai",
  "recoil",
  "immer",
  "styled-components",
  "classnames",
  "framer-motion",
  "lucide-react",
  "tailwindcss",
  "postcss",
  "autoprefixer",
  "sass",
  "node-sass",
  "less",
  "swr",
  "formik",
  "electron",
  "three",
  "leaflet",
  "chart.js",
  "d3",
  "jquery",
  // servers and HTTP
  "express",
  "express-session",
  "express-rate-limit",
  "body-parser",
  "cookie-parser",
  "cookie",
  "cors",
  "helmet",
  "compression",
  "morgan",
  "koa",
  "fastify",
  "hapi",
  "axios",
  "node-fetch",
  "cross-fetch",
  "isomorphic-fetch",
  "whatwg-fetch",
  "undici",
  "superagent",
  "request",
  "got",
  "form-data",
  "follow-redirects",
  "http-proxy",
  "http-proxy-middleware",
  "socket.io",
  "socket.io-client",
  "ws",
  "multer",
  "formidable",
  "busboy",
  "nodemailer",
  "passport",
  "passport-jwt",
  "passport-local",
  // data
  "mongoose",
  "mongodb",
  "sequelize",
  "typeorm",
  "prisma",
  "knex",
  "pg",
  "mysql",
  "mysql2",
  "mssql",
  "sqlite3",
  "better-sqlite3",
  "redis",
  "ioredis",
  "graphql",
  "apollo-server",
  "firebase",
  "firebase-admin",
  "supabase",
  "stripe",
  "openai",
  "aws-sdk",
  // security and auth
  "jsonwebtoken",
  "jwt-decode",
  "jose",
  "bcrypt",
  "bcryptjs",
  "argon2",
  "crypto-js",
  "dompurify",
  "isomorphic-dompurify",
  "sanitize-html",
  "validator",
  "uuid",
  "nanoid",
  // utilities
  "lodash",
  "underscore",
  "ramda",
  "moment",
  "dayjs",
  "date-fns",
  "luxon",
  "zod",
  "yup",
  "joi",
  "ajv",
  "qs",
  "query-string",
  "dotenv",
  "cross-env",
  "chalk",
  "colors",
  "color",
  "debug",
  "commander",
  "yargs",
  "minimist",
  "inquirer",
  "execa",
  "shelljs",
  "cross-spawn",
  "glob",
  "rimraf",
  "mkdirp",
  "fs-extra",
  "chokidar",
  "semver",
  "async",
  "bluebird",
  "rxjs",
  "tslib",
  "core-js",
  "lru-cache",
  "winston",
  "pino",
  "marked",
  "markdown-it",
  "highlight.js",
  "prismjs",
  "handlebars",
  "ejs",
  "pug",
  "cheerio",
  "jsdom",
  "puppeteer",
  "playwright",
  "sharp",
  "jimp",
  "xlsx",
  "csv-parse",
  "pdfkit",
  "node-cron",
  "bull",
  "bullmq",
  "js-yaml",
  "json5",
  "xml2js",
  // tooling
  "typescript",
  "ts-node",
  "tsx",
  "esbuild",
  "vite",
  "vitest",
  "webpack",
  "webpack-cli",
  "rollup",
  "babel-cli",
  "babel-loader",
  "eslint",
  "prettier",
  "jest",
  "mocha",
  "chai",
  "sinon",
  "supertest",
  "nock",
  "cypress",
  "nodemon",
  "concurrently",
  "husky",
  "lint-staged",
  "grunt-cli",
];

/**
 * Real packages one edit away from a popular name. Never reported by the
 * edit-distance check (they may still be deliberate choices).
 */
export const LEGITIMATE_NEIGHBOURS: readonly string[] = [
  "preact", // react
  "ms", // ws
  "ws", // ms
  "nest", // next
  "next", // nest
  "yup", // yum
  "sqlite", // sqlite3
  "jsdoc", // jsdom
  "mysql2", // mysql
  "redis", // redux
  "redux", // redis
  "color", // colors
  "colors", // color
  "cookies", // cookie
  "chalk", // chai
  "nuxt", // next
  "tslint", // eslint
  "colord", // color
  "colour", // color
  "server", // semver
  "openapi", // openai
  "mkdir", // mkdirp
  "classname", // classnames
  "globs", // glob
  "bless", // less
  "lessc", // less
  "jslint", // eslint
  "scrypt", // bcrypt
  "bcrypto", // bcrypt
  "graphiql", // graphql
  "csv-parser", // csv-parse
  "expresso", // express
  "requests", // request
  "prism", // prisma
  "strip", // stripe
  "chain", // chai
  "reactn", // react
  "axiom", // axios
  "uuid4", // uuid
  "nuxt3", // nuxt
  "mongod", // mongodb
  "marker", // marked
  "react-icon", // react-icons
];
