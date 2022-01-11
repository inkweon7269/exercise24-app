import React from 'react';
import {SubmitHandler} from "react-hook-form";
import _Login from "../../components/templates/auth/_Login";
import withHead from "../withHead";
import useStore from "../../store/useStore";
import {message} from 'antd'
import { useRouter } from 'next/router'
import {observer} from "mobx-react-lite";

export interface LoginUser {
    username: string;
    password: string;
}

const Login = observer(() => {
    const router = useRouter();
    const { user } = useStore();

    const loginCB = (isSuccess: boolean, data: any, msg: string | null) => {
        if (isSuccess) {
            router.push('/')
        } else {
            message.error(msg);
        }
    }
    const onSubmit: SubmitHandler<LoginUser> = async data => {
        await user.login(data, loginCB);
        console.log(user.token);
    };

    return (
        <_Login onSubmit={onSubmit} />
    );
});

export default withHead(Login, '우리집 | 로그인');