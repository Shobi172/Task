import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import User, { IUser } from "../models/userModel";

interface AuthenticatedRequest extends Request {
  user?: IUser;
}

const authenticateAccessToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    const accessToken = authHeader?.split(" ")[1];

    if (!accessToken) {
      return res.status(401).json({ message: "Access token not provided" });
    }

    jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET as string,
      async (error, decoded: any) => {
        if (error) {
          return res.status(401).json({ message: "Invalid access token" });
        }

        const userId = decoded.userId;

        const user = await User.findById(userId);

        if (!user) {
          return res.status(401).json({ message: "User not found" });
        }

        req.user = user;

        next();
      }
    );
  } catch (error) {
    console.error("Access token validation error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export default { authenticateAccessToken };
