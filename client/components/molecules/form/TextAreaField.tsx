import React, {FC} from 'react';
import StyledTextArea, {IPropsTextArea} from "../../atoms/form/StyledTextArea";
import {Control, Controller} from "react-hook-form";
import StyledLabel from "../../atoms/form/StyledLabel";
import StyledError from "../../atoms/form/StyledError";

interface IProps extends IPropsTextArea {
    control: Control;
    label?: string;
    name: string;
    errorMessage?: string;
}

const TextAreaField:FC<IProps> = (
    {
        control,
        label,
        name,
        placeholder,
        disabled,
        background,
        errorMessage,
        width,
        display,
    }
) => {
    return (
        <Controller
            control={control}
            name={name}
            render={({field}) => (
                <StyledLabel label={label}>
                    <StyledTextArea
                        field={field}
                        placeholder={placeholder}
                        disabled={disabled}
                        width={width}
                        display={display}
                        background={background}
                    />
                    <StyledError message={errorMessage}/>
                </StyledLabel>
            )}
        />
    );
};

export default TextAreaField;