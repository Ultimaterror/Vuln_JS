const validatePassword = (password) => {
    if (!password || password.length < 9) {
        return {
            isValid: false,
            message: 'Le mot de passe doit contenir au moins 9 caractères.'
        };
    }

    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSpecialChar = /[@/&!\-]/.test(password); // User suggested @ / & / ! / -

    if (!hasUppercase || !hasLowercase || !hasDigit || !hasSpecialChar) {
        return {
            isValid: false,
            message: 'Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial (@, /, &, !, -).'
        };
    }

    return { isValid: true, message: '' };
};

module.exports = {
    validatePassword
};
