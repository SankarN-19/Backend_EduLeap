const User = require("../models/User");
const OTP = require("../models/OTP");
const Profile = require("../models/Profile");
const otpGenerator = require("otp-generator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

//sendOTP
exports.sendOTP = async (req, res) => {
  try {
    //fetch email from request body
    const { email } = req.body;

    //check if already existing user
    const checkUserPresent = await User.findOne({ email });
    if (checkUserPresent) {
      return res.status(401).json({
        success: false,
        message: "User already registered",
      });
    }

    //generate OTP ---> brute force approach
    var otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });
    console.log("OTP generated : ", otp); //for checking purpose

    //check for unique otp or not
    const result = await OTP.findOne({ otp: otp });
    while (result) {
      otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });
      result = await OTP.findOne({ otp: otp });
    }

    //create an entry in db for OTP
    const otpPayload = { email, otp };
    const otpBody = await OTP.create(otpPayload);
    console.log(otpBody); //for checking purpose

    //return response
    return res.status(200).json({
      success: true,
      message: "OTP Sent Successfully",
      otp,
    });
  } catch (err) {
    console.log(err);
    return res.status(400).json({
      success: false,
      message: err.message,
    });
  }
};

//signup
exports.signup = async (req, res) => {
  try {
    //Data fetch from request's body
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      accountType,
      contactNumber,
      otp,
    } = req.body;

    //Validation
    if (
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !confirmPassword ||
      !otp
    ) {
      return res.status(403).json({
        success: false,
        message: "Please fill all the details!",
      });
    }

    //password match krke dekho
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message:
          "Password and COnfirmPassword value doesnot match, please try again!",
      });
    }

    //check if user already exists
    const existingUser = await User.findOne({ email });
    if (email) {
      return res.status(400).json({
        success: false,
        message: "User is already registered!",
      });
    }

    //Find most recent OTP stored for the user from the DB
    const recentOTP = await OTP.find({ email })
      .sort({ createdAt: -1 })
      .limit(1);
    console.log(recentOTP);

    //validate otp
    if (recentOTP.length == 0) {
      //OTP not found
      return res.status(400).json({
        success: false,
        message: "OTP Not found.",
      });
    } else if (otp !== recentOTP) {
      //invalid otp
      return res.status(400).json({
        success: false,
        message: "Invalid OTP.",
      });
    }

    //Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    //create entry in DB
    const profileDetails = await Profile.create({
      gender: null,
      dateOfBirth: null,
      about: null,
      contactNumber: null,
    });

    const user = await User.create({
      firstName,
      lastName,
      email,
      contactNumber,
      password: hashedPassword,
      accountType,
      additionalDetails: profileDetails._id,
      image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
    });

    //return the response
    return res.staus(200).json({
      success: true,
      message: "User is registerd successfully.",
      user,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      success: false,
      message: "User cannot be registered, please try again.",
    });
  }
};

//login
exports.login = async (req, res) => {
  try {
    //get data from req body
    const { email, password } = req.body;
    //validation
    if (!email || !password) {
      return res.status(403).json({
        success: false,
        message: "All fields are required, please try again",
      });
    }
    //user check
    const user = await User.findOne({ email }).populate("additionalDetails");
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User is not registered, please signup first",
      });
    }
    //generate JWT, after password matching
    if (await bcrypt.compare(password, user.password)) {
      const payload = {
        email: user.email,
        id: user._id,
        accountType: user.accountType,
      };
      const token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });
      user.token = token;
      user.password = undefined;

      //Create cookie and send response

      const options = {
        expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
        httpOnly: true,
      };
      res.cookie("token", token, options).status(200).json({
        success: true,
        token,
        user,
        message: "User Logged in successfully",
      });
    } else {
      return res.status(403).json({
        success: false,
        message: "Incorrect Password.",
      });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      success: false,
      message: "Login Failure, please try again.",
    });
  }
};

//changePassword
