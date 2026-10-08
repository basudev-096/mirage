"use client"

import Component from "@/components/inputotp2"
import { Button } from "@/components/ui/button"
import { GalleryVerticalEndIcon } from "lucide-react"
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { authClient } from "@/lib/auth-client";
import AlertGradient from "@/components/shadcn-space/alert/alert-06";
import SuccessDialog from "@/components/success-dialog";

type Alert = {
    title: string;
    description: string;
    type: "error" | "success";
};

export default function VerifyEmailPage() {
    const searchParams = useSearchParams();
    const email = searchParams.get("email") as string;
    const [otp, setOtp] = useState("");
    const [alert, setAlert] = useState<Alert | null>(null);
    const [showSuccessDialog, setShowSuccessDialog] = useState(false);
    const router = useRouter();

    const handleVerifyEmail = async () => {
        const { data, error } = await authClient.emailOtp.verifyEmail({
            email,
            otp
        });

        if (error) {
            setAlert({
                title: "Error",
                description: error.message || "Otp validation failed.",
                type: "error",
            });
            return;
        }

        setAlert(null);
        setShowSuccessDialog(true);

        setTimeout(() => {
            router.push("/login");
        }, 3000);
    }

    const handleResendOtp = async () => {
        setAlert(null);
        const { error } = await authClient.emailOtp.sendVerificationOtp({
            email,
            type: "email-verification"
        });

        if (error) {
            setAlert({
                title: "Error",
                description: error.message || "Failed to resend OTP.",
                type: "error",
            });
        } else {
            setAlert({
                title: "Success",
                description: "A new OTP has been sent to your email.",
                type: "success",
            });
        }
    };

    return (
        <>
            {alert && <AlertGradient {...alert} />}
            <SuccessDialog open={showSuccessDialog} />
            <div className="grid min-h-svh lg:grid-cols-2">
                <div className="flex flex-col gap-4 p-6 md:p-10">
                    <div className="flex justify-center gap-2 md:justify-start">
                        <a href="#" className="flex items-center gap-2 font-medium">
                            <div className="flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
                                <GalleryVerticalEndIcon className="size-4" />
                            </div>
                            MIRAGE
                        </a>
                    </div>
                    <div className="flex flex-1 items-center justify-center">
                        <div className="flex flex-col items-center gap-6 max-w-sm w-full">
                            <div className="flex flex-col items-center gap-2 text-center">
                                <h1 className="text-2xl font-bold">Verify your email</h1>
                                <p className="text-sm text-muted-foreground text-balance">
                                    We've sent a 6-digit verification code to your email address: {email}.
                                </p>
                            </div>

                            <Component handleChange={setOtp} />

                            <Button className="w-full mt-4" type="button" onClick={handleVerifyEmail}>
                                Verify Email
                            </Button>

                            <p className="text-sm text-muted-foreground">
                                Didn't receive the code? <button type="button" onClick={handleResendOtp} className="text-primary hover:underline font-medium">Resend</button>
                            </p>
                        </div>
                    </div>
                </div>
                <div className="relative hidden bg-muted lg:block">
                    <img
                        loading="lazy" decoding="async"
                        src="https://images.unsplash.com/photo-1698044048234-2e7f6c4e6aca?q=80&w=1000&auto=format"
                        alt="Blog Post Image"
                        className="size-full object-cover"
                    />
                </div>
            </div>
        </>
    )
}
