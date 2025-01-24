const jwt = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/User");

//auth
exports.auth = async (req, res, next) => {
  try {
    const token =
      req.body.token ||
      req.cookie.token ||
      req.header("Authorization").replace("Bearer ", "");

    //If token is not present, then send response
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token is missing!",
      });
    }

    //verify the token
    try {
      const decode = jwt.verify(token, process.env.JWT_SECRET);
      console.log(decode); //for checking purpose

      req.user = decode;
    } catch (error) {
      //verification issue
      return res.status(401).json({
        success: false,
        message: "Token is invalid",
      });
    }
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Something went wrong, while verifying the token",
    });
  }
};

//isStudent
exports.isStudent = (req, res, next) => {
  try {
    if (req.user.accountType !== "Student") {
      return res.status(401).json({
        success: false,
        message: "This is a protected route for students only",
      });
    }
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "User role cannot be verified, please try again.",
    });
  }
};

//isInstructor
exports.isInstructor = (req, res, next) => {
    try {
      if (req.user.accountType !== "Instructor") {
        return res.status(401).json({
          success: false,
          message: "This is a protected route for Instructor only",
        });
      }
      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "User role cannot be verified, please try again.",
      });
    }
  };

//isAdmin
exports.isAdmin = (req, res, next) => {
    try {
      if (req.user.accountType !== "Admin") {
        return res.status(401).json({
          success: false,
          message: "This is a protected route for Admin only",
        });
      }
      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "User role cannot be verified, please try again.",
      });
    }
  };
