import { ApiResponse } from "../utils/Response/ApiResponse.js";
import { ApiError } from "../utils/Error/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import User from "../models/user.model.js";
import {
  ACCESS_TOKEN_EXPIRY_TIME,
  REFRESH_TOKEN_EXPIRY_TIME,
  SECURE_COOKIE_OPTION,
  USER_ROLE_TYPE,
} from "../constants.js";
import { isValidObjectId } from "../utils/helpers.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;

    // LEARN : It turn off validation rule because we want to save only few fields and does not run validation rule
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

export const register = asyncHandler(async (req, res) => {
  console.log("Register Route");
  const { username, email, password, role, contact, state } = req.body;
  console.table({ username, email, password, role, contact, state });

  if (
    ![username, email, password].every((field) => field && field.trim() !== "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  // console.log(`🚀 ~ registerUser ~ existedUser:`, existedUser);

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }
  // LEARN : For registration create() is used.
  const user = await User.create({
    email,
    password,
    username,
    role,
    contact,
    state,
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User Registered Successfully"));
});

export const login = asyncHandler(async (req, res) => {
  console.log("Login Route");

  const { username, password } = req.body;
  console.table({ username, password });

  if (!username) {
    throw new ApiError(400, "Username or Email is required");
  }

  if (!password) {
    throw new ApiError(400, "Password is required");
  }

  // strict search
  // const user = await User.findOne({
  //   $or: [
  //     { username: { $regex: new RegExp(`^${username}$`) } },
  //     { email: { $regex: new RegExp(`^${username}$`) } },
  //   ],
  // });

  // not strict search
  const user = await User.findOne({
    $or: [{ username }, { email: username }],
  });

  // console.log(`🚀 ~ loginUser ~ user:`, user);

  if (!user) {
    throw new ApiError(401, "Invalid credentials");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid credentials");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  // LEARN : Send multiple cookies
  return res
    .status(200)
    .cookie("accessToken", accessToken, {
      ...SECURE_COOKIE_OPTION,
      expires: new Date(Date.now() + ACCESS_TOKEN_EXPIRY_TIME),
    })
    .cookie("refreshToken", refreshToken, {
      ...SECURE_COOKIE_OPTION,
      expires: new Date(Date.now() + REFRESH_TOKEN_EXPIRY_TIME),
    })
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User Logged In Successfully"
      )
    );
});

export const getAllUsers = asyncHandler(async (req, res) => {
  console.log("GetAllUser Route");

  const data = await User.find({}).select("-password -refreshToken");
  // console.log(`🚀 ~ getAllUser ~ data:`, data);

  return res
    .status(200)
    .json(new ApiResponse(200, data, "All Users fetched successfully"));
});

export const getUserDetails = asyncHandler(async (req, res) => {
  console.log("GetUserDetails Route");
  const { id } = req.params;
  // console.log(`🚀 ~ getUserDetails ~ id:`, id);

  if (!isValidObjectId(id)) {
    throw new ApiError(400, "Invalid MongoDB ObjectID");
  }

  const data = await User.findById(id).select("-password -refreshToken");
  // console.log(`🚀 ~ getUserDetails ~ data:`, data);

  if (!data) {
    throw new ApiError(404, "User not found");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, data, "User Details fetched successfully"));
});

export const logout = asyncHandler(async (req, res) => {
  console.log("Logout Route");
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1, // this removes the field from document
      },
    },
    { new: true }
  );

  return res
    .status(200)
    .clearCookie("accessToken", SECURE_COOKIE_OPTION)
    .clearCookie("refreshToken", SECURE_COOKIE_OPTION)
    .json(new ApiResponse(200, {}, "User Logged Out Successfully"));
});

export const updateAccountDetails = asyncHandler(async (req, res) => {
  // DESC : Here, both fullName and email is required to update the data

  const { contact, state } = req.body;

  if (!contact && !state) {
    throw new ApiError(
      400,
      "Please provide either contact or state to update details"
    );
  }

  const { id } = req.params;
  console.log(`🚀 ~ updateAccountDetails ~ id:`, id, "=>", req.user?._id);

  const condition = id || req.user?._id;
  console.log(`🚀 ~ updateAccountDetails ~ condition:`, condition);

  if (!isValidObjectId(condition)) {
    throw new ApiError(400, "Invalid MongoDB ObjectID");
  }
  const user = await User.findByIdAndUpdate(
    condition,
    {
      $set: {
        contact,
        state,
      },
    },
    {
      new: true,
      runValidators: true, // This line ensures that validators are run
    }
  ).select("-password -refreshToken");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Account Details updated successfully"));
});

export const checkUsername = asyncHandler(async (req, res) => {
  console.log("checkUsername Route");

  const { username } = req.query;
  console.log(`🚀 ~ checkUsername ~ username:`, username);

  const existingUser = await User.findOne({ username }).select("username");
  console.log(`🚀 ~ checkUsername ~ existingUser:`, existingUser);

  if (existingUser) {
    throw new ApiError(409, "Username Already Exists");
  }

  return res
    .status(200)
    .json(
      new ApiResponse(200, null, `The username '${username}' is available.`)
    );
});

export const deleteUserRecord = asyncHandler(async (req, res) => {
  console.log("deleteUserRecord Route");

  const { id } = req.params;
  let result;
  // console.log(`🚀 ~ deleteUserRecord ~ id:`, id);
  const condition = id || req.user?._id;
  // console.log(`🚀 ~ deleteUserRecord ~ condition:`, condition);

  if (!isValidObjectId(condition)) {
    throw new ApiError(400, "Invalid MongoDB ObjectID");
  }
  if (!id) {
    result = await User.deleteRecord(condition);
  } else {
    result = await User.deleteRecord(condition, USER_ROLE_TYPE.Admin);
  }

  if (result.status) {
    // return res
    //   .status(200)
    //   .clearCookie("accessToken", SECURE_COOKIE_OPTION)
    //   .clearCookie("refreshToken", SECURE_COOKIE_OPTION)
    //   .json(new ApiResponse(200, {}, "User Deleted Successfully"));

    if (!id) {
      // Delete own record => delete both cookies
      return res
        .status(200)
        .clearCookie("accessToken", SECURE_COOKIE_OPTION)
        .clearCookie("refreshToken", SECURE_COOKIE_OPTION)
        .json(new ApiResponse(200, {}, "User Deleted Successfully"));
    }

    // Delete other record (by admin) => don't delete any cookies
    return res
      .status(200)
      .json(new ApiResponse(200, {}, "User Deleted Successfully (by Admin)"));
  } else {
    throw new ApiError(result.statusCode, result.message);
  }
});

export const getCurrentUser = asyncHandler(async (req, res) => {
  console.log("getCurrentUser Route");
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "User fetched successfully"));
});

export const newAccessToken = asyncHandler(async (req, res) => {
  try {
    console.log("newAccessToken Route");
    console.log("ck = ", req.cookies);
    console.log("headers = ", req.header("Authorization"));
    console.log("Vikas = ", req.header);
    console.log("Rani = ", req.headers);
    console.log("body = ", req.body);

    const incomingRefreshToken =
      req.cookies?.refreshToken ||
      req.header("Authorization")?.replace("Bearer ", "") ||
      req.body.refreshToken;

    console.log(
      `🚀 ~ newAccessToken ~ incomingRefreshToken:`,
      incomingRefreshToken
    );

    if (!incomingRefreshToken) {
      throw new ApiError(401, "UnAuthorized : Refresh Token is required");
    }

    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
    console.log(`🚀 ~ newAccessToken ~ decodedToken:`, decodedToken);

    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "UnAuthorized : Invalid Refresh Token");
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      console.log("Refresh token not matched with db ❌");
      throw new ApiError(
        401,
        "UnAuthorized : Refresh token is expired or used"
      );
    }

    console.log("Refresh token matched with db ✅");

    // generate new access token
    const newAccessToken = user.generateAccessToken();
    console.log(`🚀 ~ newAccessToken ~ newAccessToken:`, newAccessToken);

    return res
      .status(200)
      .cookie("accessToken", newAccessToken, {
        ...SECURE_COOKIE_OPTION,
        expires: new Date(Date.now() + ACCESS_TOKEN_EXPIRY_TIME),
      })
      .json(
        new ApiResponse(
          200,
          { accessToken: newAccessToken },
          "New Access Token Generated Successfully"
        )
      );
  } catch (error) {
    // console.log("Error aala = ", error);
    // LEARN : When refresh token is expired then clear both cookies (accessToken, refreshToken)
    if (error instanceof jwt.TokenExpiredError) {
      res
        .clearCookie("accessToken", SECURE_COOKIE_OPTION)
        .clearCookie("refreshToken", SECURE_COOKIE_OPTION);

      throw new ApiError(401, "UnAuthorized : Refresh Token Expired");
    }
    throw error;
  }
});
