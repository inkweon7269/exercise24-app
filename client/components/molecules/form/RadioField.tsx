import React, {FC} from 'react';
import StyledRadio, {IPropsRadio} from "../../atoms/form/StyledRadio";
import {Control, Controller} from "react-hook-form";
import StyledLabel from "../../atoms/form/StyledLabel";
import StyledError from "../../atoms/form/StyledError";

interface IProps extends IPropsRadio {
    control: Control;
    label?: string;
    name: string;
    errorMessage?: string;
}

const RadioField: FC<IProps> = ({
                                    control,
                                    label,
                                    name,
                                    options,
                                    onChange,
                                    errorMessage,
                                }) => {
    return (
        <Controller
            control={control}
            name={name}
            render={({field}) => (
                <StyledLabel label={label}>
                    <StyledRadio
                        field={field}
                        options={options}
                        onChange={onChange}
                    />
                    <StyledError message={errorMessage}/>
                </StyledLabel>
            )}
        />
    );
};

export default RadioField;