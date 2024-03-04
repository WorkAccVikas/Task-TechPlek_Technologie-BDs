import { ApiError } from "../utils/Error/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import { USER_ROLE_TYPE } from "../constants.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    /** DESC :
     *  Access token come from either browser or mobile
     *  - for browser = cookie
     *  - for mobile = header
     *  */
    console.log("verifyJWT middleware");
    console.log("cookies = ", req.cookies);
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");

    // console.log("Auth middleware ::: token ::: ", token);

    if (!token) {
      throw new ApiError(401, "Unauthorized request");
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    // console.log(`🚀 ~ verifyJWT ~ decodedToken:`, decodedToken)

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );

    if (!user) {
      throw new ApiError(401, "Invalid Access Token");
    }

    req.user = user;

    next();
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid access token");
  }
});

export const verifyAdminRole = asyncHandler(async (req, res, next) => {
  try {
    // Get user object from the request
    const user = req.user;
    console.log("verifyAdminRole middleware");

    // Check if the user has the Admin role
    if (user.role !== USER_ROLE_TYPE.Admin) {
      throw new ApiError(
        403,
        "You do not have permission to perform this action"
      );
    }

    // If the user has Admin role, allow the request to proceed
    next();
  } catch (error) {
    // If there's an error, return it as an ApiError
    next(new ApiError(403, error?.message || "Forbidden"));
  }
});
