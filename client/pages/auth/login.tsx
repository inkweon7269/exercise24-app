import React from 'react';
import {SubmitHandler} from "react-hook-form";
import _Login from "../../components/templates/auth/_Login";
import withHead from "../withHead";

export interface LoginUser {
    username: string;
    password: string;
}

const Login = () => {
    const onSubmit: SubmitHandler<LoginUser> = async data => {
        console.log(data);
    };

    return (
        <_Login onSubmit={onSubmit} />
    );
};

export default withHead(Login, '우리집 | 로그인');