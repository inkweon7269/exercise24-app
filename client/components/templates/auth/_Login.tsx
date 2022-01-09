import React, {FC} from 'react';
import {useForm, FormProvider} from "react-hook-form";
import {Form} from "antd";
import { yupResolver } from '@hookform/resolvers/yup';
import LoginWrapper from "../../organisms/auth/LoginWrapper";
import {loginSchema} from "../../../validation/schema";

type IProps = {
    onSubmit: (data: any) => void
}

const _Login: FC<IProps> = ({onSubmit}) => {

    const formMethods = useForm({
        resolver: yupResolver(loginSchema)
    });

    const {handleSubmit} = formMethods;

    return (
        <FormProvider {...formMethods}>
            <Form
                layout='vertical'
                onFinish={handleSubmit(onSubmit)}
            >
                <LoginWrapper />
            </Form>
        </FormProvider>
    );
};

export default _Login;