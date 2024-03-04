import { Router } from "express";
import {
  login,
  register,
  getAllUsers,
  getUserDetails,
  logout,
  updateAccountDetails,
  checkUsername,
  deleteUserRecord,
  getCurrentUser,
  newAccessToken,
} from "../controllers/user.controller.js";
import { verifyAdminRole, verifyJWT } from "../middlewares/auth.middleware.js";
const router = Router();

router.route("/register").post(register);

router.route("/login").post(login);

router.route("/newAccessToken").get(newAccessToken);

// PROTECTED ROUTES
router
  .route("/")
  // .get(verifyJWT, verifyAdminRole, getAllUsers)
  .get(
    (req, res, next) => {
      // Check if query parameter exists
      if (req.query.username) {
        // If query parameter exists, only call checkUsername controller
        checkUsername(req, res, next);
      } else {
        // If no query parameter, proceed with middleware and controller chain
        next();
      }
    },
    verifyJWT,
    verifyAdminRole,
    getAllUsers
  )
  .patch(verifyJWT, updateAccountDetails)
  .delete(verifyJWT, deleteUserRecord);

router.route("/currentUser").get(verifyJWT, getCurrentUser);

router
  .route("/:id")
  .get(verifyJWT, getUserDetails)
  .patch(verifyJWT, verifyAdminRole, updateAccountDetails)
  .delete(verifyJWT, verifyAdminRole, deleteUserRecord);

router.route("/logout").post(verifyJWT, logout);

export default router;
