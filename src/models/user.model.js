import { Schema, model } from "mongoose";
import {
  MAX_PASSWORD_LENGTH,
  ROLES_ENUM,
  USER_ROLE_TYPE,
} from "../constants.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { ApiError } from "../utils/Error/ApiError.js";

const userSchema = new Schema(
  {
    username: {
      type: String,
      unique: [true, "Please provide a unique username"],
      required: [true, "Username is required"],
      trim: true,
      lowercase: true,
      index: true,
    },
    email: {
      type: String,
      unique: [true, "Please provide a unique email"],
      trim: true,
      lowercase: true,
      validate: {
        validator: function (v) {
          return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(v);
        },
        message: "Please enter a valid email",
      },
      required: [true, "Email is required"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      trim: true,
      minlength: [
        MAX_PASSWORD_LENGTH,
        "Password should be at least 5 characters long",
      ],
    },
    role: {
      type: String,
      enum: ROLES_ENUM,
      default: USER_ROLE_TYPE.User,
    },
    refreshToken: {
      type: String,
    },
    contact: {
      type: String,
      minLength: [10, "Contact number should have minimum 10 digits"],
      maxLength: [10, "Contact number should have maximum 10 digits"],
      match: [/\d{10}/, "Contact number should only contain digits"],
    },
    state: {
      type: String,
      set: (value) =>
        value?.charAt(0)?.toUpperCase() + value?.slice(1) || undefined,
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  console.log("Pre save hook called");
  // DESC : If password is not modified the return immediately
  if (!this.isModified("password")) return next();
  console.log("Password changing");
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      role: this.role,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      role: this.role,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

userSchema.statics.deleteRecord = async function (
  userId,
  role = USER_ROLE_TYPE.User
) {
  try {
    // console.log("deleteRecord function = ", userId);

    const existingUser = await this.findById(userId);
    // console.log(
    //   `🚀 ~ userSchema.statics.deleteRecord ~ existingUser:`,
    //   existingUser
    // );

    if (!existingUser) {
      console.log("User not found........");
      // throw new ApiError(404, "User not found");
      return { status: false, statusCode: 404, message: "User not found" };
    }

    // console.log("Rani = ", existingUser._id);
    if (role === USER_ROLE_TYPE.Admin) {
      // console.log("Admin.........");
      await this.findByIdAndDelete(userId);
      return {
        status: true,
        statusCode: 200,
      };
    } else {
      // console.log("User..........", existingUser._id.equals(userId));
      // LEARN : both id are mongoose id
      if (existingUser._id.equals(userId)) {
        // Delete the own Record
        await this.findByIdAndDelete(userId);
        return {
          status: true,
          statusCode: 200,
        };
      } else {
        return {
          status: false,
        };
      }
    }
  } catch (error) {
    // throw new ApiError(500, "Internal Server Error");
  }
};

const User = new model("User", userSchema, "User");

export default User;
