import { Router } from "express"
import {
    registerUser,
    loginUser,
    logoutUser,
    deleteUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails

} from "../controllers/user.controllers.js"
import { verifyJWT } from "../middlewares/auth.middlewares.js"

const router = Router ()


//Unsecured routes: accessed by anyone
router.route("/register").post(registerUser)

router.route("/login").post(loginUser)

router.route("/refresh-token").post(refreshAccessToken)



//secured routes
router.route("/logout").post(verifyJWT, logoutUser)


router.route("/change-password").post(verifyJWT, changeCurrentPassword)

router.route("/current-user").get(verifyJWT, getCurrentUser)

router.route("/update-account").patch(verifyJWT, updateAccountDetails )

router.route("/delete-account").post(verifyJWT, deleteUser)


export default router