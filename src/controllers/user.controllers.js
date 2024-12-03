import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import {User} from "../models/user.models.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import mongoose from "mongoose"
import jwt from "jsonwebtoken"

const generateAccessAndRefereshTokens = async(userId) =>{
    try {
        const user = await User.findById(userId)
        //console.log(user)
        const accessToken = user.generateAccessToken() 
        //console.log(accessToken)
        const refreshToken = user.generateRefreshToken()

        try {
            user.refreshToken = refreshToken
            await user.save({ validateBeforeSave: false })
        } catch (error) {
            console.log("Error saving user: , error")
        }

        return {accessToken, refreshToken}


    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}

const registerUser = asyncHandler(async (req, res)=>{

    // console.log(req.body)
    const { username, email, password} = req.body
    // console.log(username, email, password)

    //validation
    if(
        [username, email, password].some((field)=>field?.trim() === "")
    ){
        throw new ApiError(400, "All fields are reqired")
    }

    //for existing user
    const existedUser = await User.findOne({
        $or: [{email},{username}]
    })

    if (existedUser){
        throw new ApiError(409, "User with email or username already exists")
    }

    try {
        const user = await User.create({
            username: username.toLowerCase(),
            email,
            password
        })
    
        const createdUser = await User.findById(user._id).select(
            "-password -refreshToken"
        )
        if (!createdUser){
            throw new ApiError(500, "Something went wrong while registering a user")
        }
        return res
        .status(201)
        .json(new ApiResponse(200, createdUser, "User registered successfully"))
    } catch (error) {
        console.log("User creation failed")

        throw new ApiError(500, "Something went wrong while registering a user")
    }

})

const loginUser = asyncHandler(async (req, res) =>{
    // req body -> data
    // username or email
    //find the user
    //password check
    //access and referesh token
    //send cookie

    const {email, username, password} = req.body

    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }
    
    // Here is an alternative of above code based on logic discussed in video:
    // if (!(username || email)) {
    //     throw new ApiError(400, "username or email is required")
        
    // }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

   const isPasswordValid = await user.isPasswordCorrect(password)

   if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials")
    }

   const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200, 
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully"
        )
    )

})

const logoutUser = asyncHandler(async (req, res)=>{
    await User.findByIdAndUpdate(
            req.user._id,
            {
                $set: {
                    refreshToken: ""   //undefined or "" based on version of mongodb
                }
            },
            {new: true}
        )

        const options ={
            httpOnly: true,
            secure: process.env.NODE_ENV === "development"
        }

        return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"))
})

const refreshAccessToken = asyncHandler(async (req, res)=>{
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Refresh token is required")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET ,
        )

        const user = await User.findById(decodedToken?._id)

        if(!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
        //console.log(user._id)
        
        if (incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Invalid refresh token")
        }
        
        const options = {
            httpOnly: true,
            secure: true, //process.env.NODE_ENV === "development",
        }
        

        const {accessToken, refreshToken: newRefreshToken} = await generateAccessAndRefereshTokens(user._id)

        return res 
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken,
                     refreshToken: newRefreshToken
                },
                 "Access token refreshed successfully"
                )
            );

    } catch (error) {
        throw new ApiError(500, "Something went wrong while refreshing access token")
    }
})

const changeCurrentPassword = asyncHandler(async(req, res)=> {
    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id)

    const isPasswordValid = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordValid){
        throw new ApiError(401, "Old password is incorrect")
    }

    user.password = newPassword;

    await user.save({validateBeforeSAve: false})

    return res
    .status(200)
    .json(new ApiResponse (200, {}, "Password changed successfully"))

})

const getCurrentUser = asyncHandler(async(req, res)=> {
    return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current user details"))
})

const updateAccountDetails = asyncHandler(async(req, res)=> {
    const {email} = req.body

    if(!email){
        throw new ApiError(400, "Email required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                email: email.toLowerCase()
            }
        },
        {new: true}
    ).select("-password -refreshToken")

    return res
    .status(200)
    .json( new ApiResponse(200, user, "Account details updated successfully"))
})

const deleteUser = asyncHandler(async (req, res) => {
    const userId = req.user?._id; // Assuming req.user contains the authenticated user's details

    if (!userId) {
        throw new ApiError(400, "User ID is required");
    }

    try {
        const user = await User.findByIdAndDelete(userId);

        if (!user) {
            throw new ApiError(404, "User not found");
        }

        // Clear cookies after deleting the user
        const options = {
            httpOnly: true,
            secure: process.env.NODE_ENV === "development",
        };

        return res
            .status(200)
            .clearCookie("accessToken", options)
            .clearCookie("refreshToken", options)
            .json(new ApiResponse(200, {}, "User account deleted successfully"));
    } catch (error) {
        throw new ApiError(500, "Something went wrong while deleting the user");
    }
});




export { 
    registerUser,
    loginUser,
    logoutUser,
    deleteUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails
 }