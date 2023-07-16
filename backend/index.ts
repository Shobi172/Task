import dotenv from "dotenv";
dotenv.config();
import express from "express";
import connectDB from "./config/db";
import userRoutes from "./routes/userRoutes";

const app = express();

connectDB();

app.use(express.json());

app.use("/users", userRoutes);

const port = 5000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
