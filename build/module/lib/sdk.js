import axios from 'axios';
import * as Cookies from 'js-cookie';
import * as qs from 'qs';
export default class Strapi {
    /**
     * Default constructor.
     * @param baseURL Your Strapi host.
     * @param axiosConfig Extend Axios configuration.
     */
    constructor(baseURL, storeConfig, requestConfig) {
        this.axios = axios.create({
            baseURL,
            paramsSerializer: qs.stringify,
            ...requestConfig
        });
        this.storeConfig = {
            cookie: {
                key: 'jwt',
                options: {
                    path: '/'
                }
            },
            localStorage: {
                key: 'jwt'
            },
            ...storeConfig
        };
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
            const response = await this.axios.request({
                method,
                url,
                ...requestConfig
            });
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
    async register(username, email, password, firstname, lastname, company, optin) {
        this.clearToken();
        const authentication = await this.request('post', '/auth/local/register', {
            data: {
                email,
                password,
                username,
                firstname,
                lastname,
                company,
                optin
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
        return this.request('post', '/upload', {
            data,
            ...requestConfig
        });
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2RrLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9zZGsudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxLQUEyRCxNQUFNLE9BQU8sQ0FBQztBQUNoRixPQUFPLEtBQUssT0FBTyxNQUFNLFdBQVcsQ0FBQztBQUNyQyxPQUFPLEtBQUssRUFBRSxNQUFNLElBQUksQ0FBQztBQTZCekIsTUFBTSxDQUFDLE9BQU8sT0FBTyxNQUFNO0lBSXpCOzs7O09BSUc7SUFDSCxZQUNFLE9BQWUsRUFDZixXQUF5QixFQUN6QixhQUFrQztRQUVsQyxJQUFJLENBQUMsS0FBSyxHQUFHLEtBQUssQ0FBQyxNQUFNLENBQUM7WUFDeEIsT0FBTztZQUNQLGdCQUFnQixFQUFFLEVBQUUsQ0FBQyxTQUFTO1lBQzlCLEdBQUcsYUFBYTtTQUNqQixDQUFDLENBQUM7UUFDSCxJQUFJLENBQUMsV0FBVyxHQUFHO1lBQ2pCLE1BQU0sRUFBRTtnQkFDTixHQUFHLEVBQUUsS0FBSztnQkFDVixPQUFPLEVBQUU7b0JBQ1AsSUFBSSxFQUFFLEdBQUc7aUJBQ1Y7YUFDRjtZQUNELFlBQVksRUFBRTtnQkFDWixHQUFHLEVBQUUsS0FBSzthQUNYO1lBQ0QsR0FBRyxXQUFXO1NBQ2YsQ0FBQztRQUVGLElBQUksSUFBSSxDQUFDLFNBQVMsRUFBRSxFQUFFO1lBQ3BCLElBQUksYUFBYSxDQUFDO1lBQ2xCLElBQUksSUFBSSxDQUFDLFdBQVcsQ0FBQyxNQUFNLEVBQUU7Z0JBQzNCLGFBQWEsR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO2FBQzFEO2lCQUFNLElBQUksSUFBSSxDQUFDLFdBQVcsQ0FBQyxZQUFZLEVBQUU7Z0JBQ3hDLGFBQWEsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUMsT0FBTyxDQUNwRCxJQUFJLENBQUMsV0FBVyxD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