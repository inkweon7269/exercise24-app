import React, {FC} from 'react';
import {Control, Controller} from "react-hook-form";
import StyledError from "../../atoms/form/StyledError";
import StyledInput, {IPropsInput} from "../../atoms/form/StyledInput";
import StyledLabel from "../../atoms/form/StyledLabel";

interface IProps extends IPropsInput {
    control: Control;
    label?: string;
    type?: string;
    name: string;
    errorMessage?: string;
}

const TextField: FC<IProps> = (
    {
        control,
        label,
        name,
        type,
        placeholder,
        disabled,
        background,
        errorMessage,
        min,
        max,
        width,
        display
    }
) => {
    return (
        <Controller
            control={control}
            name={name}
            render={({field}) => (
                <StyledLabel label={label}>
                    <StyledInput
                        field={field}
                        type={type}
                        placeholder={placeholder}
                        disabled={disabled}
                        background={background}
                        min={min}
                        max={max}
                        width={width}
                        display={display}
                    />
                    <StyledError message={errorMessage}/>
                </StyledLabel>
            )}
        />
    );
};

export default TextField;