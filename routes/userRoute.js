import express from "express";
const router = express.Router();
import {
  signUp,
  signIn,
  verifyUser,
  requestNewOTP,
  protectRoute,
  forgeetPassword,
  verifyResetPassword,
  resetPassword,
} from "../controllers/userController.js";

router.post("/signUp", signUp);
router.post("/signIn", signIn);
router.post("/verifyUser", verifyUser);
router.post("/requestNewOTP", requestNewOTP);
router.post("/forgetPassword", forgeetPassword);
router.post("/verifyResetPassword", verifyResetPassword);
router.post("/resetPassword", resetPassword);
export default router;
