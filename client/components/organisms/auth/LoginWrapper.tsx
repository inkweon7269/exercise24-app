import React from 'react';
import {useFormContext} from "react-hook-form";
import TextField from "../../molecules/form/TextField";
import ButtonField from "../../molecules/form/ButtonField";
import {UserAddOutlined} from "@ant-design/icons";
import styled from "styled-components";

const LoginWrapper = () => {
    const {control, watch, getValues, setValue, formState: {errors}} = useFormContext();

    return (
        <Login>
            <TextField
                control={control}
                label='이메일'
                name='email'
                errorMessage={errors.email?.message}
            />

            <TextField
                control={control}
                label='비밀번호'
                name='password'
                type='password'
                errorMessage={errors.password?.message}
            />

            <ButtonField
                text='로그인'
                type='primary'
                htmlType='submit'
                size='large'
                icon={<UserAddOutlined/>}
                block
            />
        </Login>
    );
};

export default LoginWrapper;

const Login = styled.div`
  width: 300px;
  margin: 0 auto;
`;