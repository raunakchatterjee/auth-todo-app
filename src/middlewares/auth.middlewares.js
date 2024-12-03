import jwt from "jsonwebtoken"
import {User} from "../models/user.models.js"
import { ApiError } from "../utils/ApiError.js"
import { asyncHandler } from "../utils/asyncHandler.js"
import { loginUser } from "../controllers/user.controllers.js"


export const verifyJWT = asyncHandler(async(req, _,next)=>{
    const token = req.cookies.accessToken || req.header("Authorization")?.replace("Bearer ","")
    if(!token){
        throw new ApiError(401, "Unauthorized request")
    }

    try {
        const decodeToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET || "default access secret")

        const user = await User.findById(decodeToken?._id).select("-password -refreshToken")
        // console.log(user)
        if(!user){
            throw new ApiError(401, "Unauthorized")
        }

        req.user = user

        next()
        
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid access token")
    }

})