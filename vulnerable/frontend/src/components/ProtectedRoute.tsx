import React, { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { useUser } from "../context/UserContext";
import axiosInstance from "../services/axiosInstance";

interface ProtectedRouteProps {
    children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
    const { user } = useUser();
    const [isAdmin, setIsAdmin] = useState<boolean | null>(null);

    useEffect(() => {
        const checkAdminAccess = async () => {
            try {
                const response = await axiosInstance.get("/auth/access-admin");
                if (response.data.isAdmin) {
                    setIsAdmin(true);
                } else {
                    setIsAdmin(false);
                }
            } catch (error) {
                console.error("Admin access check failed:", error);
                setIsAdmin(false);
            }
        };

        if (user) {
            checkAdminAccess();
        } else {
            setIsAdmin(false);
        }
    }, [user]);

    if (isAdmin === null) {
        return <div className="flex justify-center items-center h-screen"><span className="loading loading-spinner loading-lg"></span></div>;
    }

    if (!isAdmin) {
        return <Navigate to="/" replace />;
    }

    return <>{children}</>;
};

export default ProtectedRoute;
