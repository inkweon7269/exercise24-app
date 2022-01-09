import React, {FC} from 'react';
import StyledButton, {IPropsButton} from "../../atoms/form/StyledButton";

const ButtonField: FC<IPropsButton> = (
    {
        text,
        type,
        htmlType,
        size,
        icon,
        block,
        loading,
        onClick,
    }
) => {
    return (
        <StyledButton
            text={text}
            type={type}
            htmlType={htmlType}
            size={size}
            icon={icon}
            block={block}
            loading={loading}
            onClick={onClick}
        />
    );
};

export default ButtonField;