import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt, { VerifyErrors } from "jsonwebtoken";
import User, { IUser } from "../models/userModel";
import { Document } from "mongoose";

const signup = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email is already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser: IUser = new User({
      email,
      password: hashedPassword,
    });
    await newUser.save();

    const accessToken = jwt.sign(
      { userId: newUser._id },
      process.env.ACCESS_TOKEN_SECRET as string,
      { expiresIn: "120s" }
    );
    const refreshToken = jwt.sign(
      { userId: newUser._id },
      process.env.REFRESH_TOKEN_SECRET as string
    );

    newUser.accessToken = accessToken;
    newUser.refreshToken = refreshToken;
    await newUser.save();

    res.status(201).json({ accessToken, refreshToken });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET as string,
      { expiresIn: "120s" }
    );
    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET as string
    );

    user.accessToken = accessToken;
    user.refreshToken = refreshToken;
    await user.save();

    res.status(200).json({ accessToken, refreshToken });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

const refreshTokens = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token is required" });
    }

    const user = await User.findOne({ refreshToken });

    if (!user) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET as string,
      async (error: VerifyErrors | null, decoded: any) => {
        if (error) {
          return res.status(401).json({ message: "Invalid refresh token" });
        }

        const userId = decoded.userId;

        if (refreshToken !== user.refreshToken) {
          return res.status(401).json({ message: "Invalid refresh token" });
        }

        const accessToken = jwt.sign(
          { userId: user._id },
          process.env.ACCESS_TOKEN_SECRET as string,
          { expiresIn: "120s" }
        );
        const newRefreshToken = jwt.sign(
          { userId: user._id },
          process.env.REFRESH_TOKEN_SECRET as string
        );

        user.accessToken = accessToken;
        user.refreshToken = newRefreshToken;
        await user.save();

        res.status(200).json({ accessToken, refreshToken: newRefreshToken });
      }
    );
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

const deleteUser = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    await User.deleteOne({ email });

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Delete user error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export default { signup, login, refreshTokens, deleteUser };
