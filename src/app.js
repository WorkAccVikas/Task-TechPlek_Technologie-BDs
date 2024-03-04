import dotenv from "dotenv";
dotenv.config({
  path: `./.env`,
});

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import requestIp from "request-ip";

const app = express();

morgan.token("custom-time", () => {
  const date = new Date(new Date().getTime() + 5.5 * 60 * 60 * 1000);
  const formattedDate = date.toISOString().replace("T", " ").slice(0, -1);
  return formattedDate;
});

const customLoggingFormat = `\n:custom-time - :method :url :status :response-time ms\n\n${"🔊".repeat(
  100
)}`;

console.log(process.env.CORS_ORIGIN);

// cors middleware
app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
    optionSuccessStatus: 200,
  })
);

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", process.env.CORS_ORIGIN);
  res.header("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE");
  res.header("Access-Control-Allow-Headers", "content-type");
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

// global middlewares
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(morgan(customLoggingFormat));
app.use(requestIp.mw());

// routes import
import { errorHandler } from "./middlewares/error.middleware.js";
import healthCheckRouter from "./routes/healthCheck.route.js";
import userRouter from "./routes/user.route.js";
// import x from "./routes/";

// routes declaration
app.use("/api/v1/healthCheck", healthCheckRouter);

app.use("/api/v1/user", userRouter);
// app.use("/api/v1/", x);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// common error handling middleware
app.use(errorHandler);

export { app };
