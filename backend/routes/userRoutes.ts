import { Router, Request, Response } from "express";
import UserController from "../controllers/UserController";
import authMiddleware from "../middleware/authMiddleware";
import { IUser } from "../models/userModel";

interface CustomRequest extends Request {
  user?: IUser;
}

const router = Router();

router.post("/signup", UserController.signup);
router.post("/login", UserController.login);
router.post("/refresh-tokens", UserController.refreshTokens);
router.delete("/delete", UserController.deleteUser);

router.get(
  "/protected",
  authMiddleware.authenticateAccessToken,
  (req: CustomRequest, res: Response) => {
    const user = req.user as IUser;
    res.json({ message: "Protected route", user });
  }
);

export default router;
