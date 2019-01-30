"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __importDefault(require("axios"));
const Cookies = __importStar(require("js-cookie"));
const qs = __importStar(require("qs"));
class Strapi {
    /**
     * Default constructor.
     * @param baseURL Your Strapi host.
     * @param axiosConfig Extend Axios configuration.
     */
    constructor(baseURL, storeConfig, requestConfig) {
        this.axios = axios_1.default.create(Object.assign({ baseURL, paramsSerializer: qs.stringify }, requestConfig));
        this.storeConfig = Object.assign({ cookie: {
                key: 'jwt',
                options: {
                    path: '/'
                }
            }, localStorage: {
                key: 'jwt'
            } }, storeConfig);
        if (this.isBrowser()) {
            let existingToken;
            if (this.storeConfig.cookie) {
                existingToken = Cookies.get(this.storeConfig.cookie.key);
            }
            else if (this.storeConfig.localStorage) {
                existingToken = JSON.parse(window.localStorage.getItem(this.storeConfig.localStorage.key));
            }
            if (existingToken) {
                this.setToken(existingToken, true);
            }
        }
    }
    /**
     * Axios request
     * @param method Request method
     * @param url Server URL
     * @param requestConfig Custom Axios config
     */
    async request(method, url, requestConfig) {
        try {
            const response = await this.axios.request(Object.assign({ method,
                url }, requestConfig));
            return response.data;
        }
        catch (error) {
            if (error.response) {
                throw new Error(error.response.data.message);
            }
            else {
                throw error;
            }
        }
    }
    /**
     * Register a new user.
     * @param username
     * @param email
     * @param password
     * @returns Authentication User token and profile
     */
    async register(username, email, password, firstname, lastname) {
        this.clearToken();
        const authentication = await this.request('post', '/auth/local/register', {
            data: {
                email,
                password,
                username,
                firstname,
                lastname
            }
        });
        this.setToken(authentication.jwt);
        return authentication;
    }
    /**
     * Login by getting an authentication token.
     * @param identifier Can either be an email or a username.
     * @param password
     * @returns Authentication User token and profile
     */
    async login(identifier, password) {
        this.clearToken();
        const authentication = await this.request('post', '/auth/local', {
            data: {
                identifier,
                password
            }
        });
        this.setToken(authentication.jwt);
        return authentication;
    }
    /**
     * Sends an email to a user with the link of your reset password page.
     * This link contains an URL param code which is required to reset user password.
     * Received link url format https://my-domain.com/rest-password?code=privateCode.
     * @param email
     * @param url Link that user will receive.
     */
    async forgotPassword(email, url) {
        this.clearToken();
        await this.request('post', '/auth/forgot-password', {
            data: {
                email,
                url
            }
        });
    }
    /**
     * Reset the user password.
     * @param code Is the url params received from the email link (see forgot password).
     * @param password
     * @param passwordConfirmation
     */
    async resetPassword(code, password, passwordConfirmation) {
        this.clearToken();
        await this.request('post', '/auth/reset-password', {
            data: {
                code,
                password,
                passwordConfirmation
            }
        });
    }
    /**
     * Retrieve the connect provider URL
     * @param provider
     */
    getProviderAuthenticationUrl(provider) {
        return `${this.axios.defaults.baseURL}/connect/${provider}`;
    }
    /**
     * Authenticate the user with the token present on the URL (for browser) or in `params` (on Node.js)
     * @param provider
     * @param params
     */
    async authenticateProvider(provider, params) {
        this.clearToken();
        // Handling browser query
        if (this.isBrowser()) {
            params = qs.parse(window.location.search, { ignoreQueryPrefix: true });
        }
        const authentication = await this.request('get', `/auth/${provider}/callback`, {
            params
        });
        this.setToken(authentication.jwt);
        return authentication;
    }
    /**
     * List entries
     * @param contentTypePluralized
     * @param params Filter and order queries.
     */
    getEntries(contentTypePluralized, params) {
        return this.request('get', `/${contentTypePluralized}`, {
            params
        });
    }
    /**
     * Get the total count of entries with the provided criteria
     * @param contentType
     * @param params Filter and order queries.
     */
    getEntryCount(contentType, params) {
        return this.request('get', `/${contentType}/count`, {
            params
        });
    }
    /**
     * Get a specific entry
     * @param contentTypePluralized Type of entry pluralized
     * @param id ID of entry
     */
    getEntry(contentTypePluralized, id) {
        return this.request('get', `/${contentTypePluralized}/${id}`);
    }
    /**
     * Create data
     * @param contentTypePluralized Type of entry pluralized
     * @param data New entry
     */
    createEntry(contentTypePluralized, data) {
        return this.request('post', `/${contentTypePluralized}`, {
            data
        });
    }
    /**
     * Update data
     * @param contentTypePluralized Type of entry pluralized
     * @param id ID of entry
     * @param data
     */
    updateEntry(contentTypePluralized, id, data) {
        return this.request('put', `/${contentTypePluralized}/${id}`, {
            data
        });
    }
    /**
     * Delete an entry
     * @param contentTypePluralized Type of entry pluralized
     * @param id ID of entry
     */
    deleteEntry(contentTypePluralized, id) {
        return this.request('delete', `/${contentTypePluralized}/${id}`);
    }
    /**
     * Search for files
     * @param query Keywords
     */
    searchFiles(query) {
        return this.request('get', `/upload/search/${decodeURIComponent(query)}`);
    }
    /**
     * Get files
     * @param params Filter and order queries
     * @returns Object[] Files data
     */
    getFiles(params) {
        return this.request('get', '/upload/files', {
            params
        });
    }
    /**
     * Get file
     * @param id ID of entry
     */
    getFile(id) {
        return this.request('get', `/upload/files/${id}`);
    }
    /**
     * Upload files
     *
     * ### Browser example
     * ```js
     * const form = new FormData();
     * form.append('files', fileInputElement.files[0], 'file-name.ext');
     * form.append('files', fileInputElement.files[1], 'file-2-name.ext');
     * const files = await strapi.upload(form);
     * ```
     *
     * ### Node.js example
     * ```js
     * const FormData = require('form-data');
     * const fs = require('fs');
     * const form = new FormData();
     * form.append('files', fs.createReadStream('./file-name.ext'), 'file-name.ext');
     * const files = await strapi.upload(form, {
     *   headers: form.getHeaders()
     * });
     * ```
     *
     * @param data FormData
     * @param requestConfig
     */
    upload(data, requestConfig) {
        return this.request('post', '/upload', Object.assign({ data }, requestConfig));
    }
    /**
     * Set token on Axios configuration
     * @param token Retrieved by register or login
     */
    setToken(token, comesFromStorage) {
        this.axios.defaults.headers.common.Authorization = 'Bearer ' + token;
        if (this.isBrowser() && !comesFromStorage) {
            if (this.storeConfig.localStorage) {
                window.localStorage.setItem(this.storeConfig.localStorage.key, JSON.stringify(token));
            }
            if (this.storeConfig.cookie) {
                Cookies.set(this.storeConfig.cookie.key, token, this.storeConfig.cookie.options);
            }
        }
    }
    /**
     * Remove token from Axios configuration
     */
    clearToken() {
        delete this.axios.defaults.headers.common.Authorization;
        if (this.isBrowser()) {
            if (this.storeConfig.localStorage) {
                window.localStorage.removeItem(this.storeConfig.localStorage.key);
            }
            if (this.storeConfig.cookie) {
                Cookies.remove(this.storeConfig.cookie.key, this.storeConfig.cookie.options);
            }
        }
    }
    /**
     * Check if it runs on browser
     */
    isBrowser() {
        return typeof window !== 'undefined';
    }
}
exports.default = Strapi;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2RrLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9zZGsudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7O0FBQUEsa0RBQWdGO0FBQ2hGLG1EQUFxQztBQUNyQyx1Q0FBeUI7QUE2QnpCLE1BQXFCLE1BQU07SUFJekI7Ozs7T0FJRztJQUNILFlBQ0UsT0FBZSxFQUNmLFdBQXlCLEVBQ3pCLGFBQWtDO1FBRWxDLElBQUksQ0FBQyxLQUFLLEdBQUcsZUFBSyxDQUFDLE1BQU0saUJBQ3ZCLE9BQU8sRUFDUCxnQkFBZ0IsRUFBRSxFQUFFLENBQUMsU0FBUyxJQUMzQixhQUFhLEVBQ2hCLENBQUM7UUFDSCxJQUFJLENBQUMsV0FBVyxtQkFDZCxNQUFNLEVBQUU7Z0JBQ04sR0FBRyxFQUFFLEtBQUs7Z0JBQ1YsT0FBTyxFQUFFO29CQUNQLElBQUksRUFBRSxHQUFHO2lCQUNWO2FBQ0YsRUFDRCxZQUFZLEVBQUU7Z0JBQ1osR0FBRyxFQUFFLEtBQUs7YUFDWCxJQUNFLFdBQVcsQ0FDZixDQUFDO1FBRUYsSUFBSSxJQUFJLENBQUMsU0FBUyxFQUFFLEVBQUU7WUFDcEIsSUFBSSxhQUFhLENBQUM7WUFDbEIsSUFBSSxJQUFJLENBQUMsV0FBVyxDQUFDLE1BQU0sRUFBRTtnQkFDM0IsYUFBYSxHQUFHLE9BQU8sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLFdBQVcsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7YUFDMUQ7aUJBQU0sSUFBSSxJQUFJLENBQUMsV0FBVyxDQUFDLFlBQVksRUFBRTtnQkFDeEMsYUFBYSxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBQyxPQUFPLENBQ3BELElBQUksQ0FBQyxXQUFXLENBQUMsWUFBWSxDQUFDLEdBQUcsQ0FDeEIsQ0FBQyxDQUFDO2FBQ2Q7WUFDRCxJQUFJLGFBQWEsRUFBRTtnQkFDakIsSUFBSSxDQUFDLFFBQVEsQ0FBQyxhQUFh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