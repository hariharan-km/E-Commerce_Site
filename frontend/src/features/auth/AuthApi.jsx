import axiosi from '../../config/axios';

// Signup
export const signup = async (cred) => {
    try {
        const res = await axiosi.post('/auth/signup', cred);
        return res.data;
    } catch (error) {
        throw error.response?.data || { message: "Signup failed" };
    }
};

// Login
export const login = async (cred) => {
    try {
        const res = await axiosi.post('/auth/login', cred);
        return res.data;
    } catch (error) {
        throw error.response?.data || { message: "Login failed" };
    }
};

// Verify OTP
export const verifyOtp = async (cred) => {
    try {
        const res = await axiosi.post('/auth/verify-otp', cred);
        return res.data;
    } catch (error) {
        throw error.response?.data || { message: "OTP verification failed" };
    }
};

// Resend OTP
export const resendOtp = async (cred) => {
    try {
        const res = await axiosi.post('/auth/resend-otp', cred);
        return res.data;
    } catch (error) {
        throw error.response?.data || { message: "OTP resend failed" };
    }
};

// Forgot Password
export const forgotPassword = async (cred) => {
    try {
        const res = await axiosi.post('/auth/forgot-password', cred);
        return res.data;
    } catch (error) {
        throw error.response?.data || { message: "Password reset request failed" };
    }
};

// Reset Password
export const resetPassword = async (cred) => {
    try {
        const res = await axiosi.post('/auth/reset-password', cred);
        return res.data;
    } catch (error) {
        throw error.response?.data || { message: "Password reset failed" };
    }
};

// Check Auth
export const checkAuth = async () => {
    try {
        const res = await axiosi.get('/auth/check-auth');
        return res.data;
    } catch (error) {
        throw error.response?.data || { message: "Auth check failed" };
    }
};

// Logout
export const logout = async () => {
    try {
        const res = await axiosi.get('/auth/logout');
        return res.data;
    } catch (error) {
        throw error.response?.data || { message: "Logout failed" };
    }
};
