const Boom = require( '@hapi/boom' ),
	JsonWebToken = require( 'jsonwebtoken' ),
	DbCrud = require( '@dmidz/crud' ),
	bcrypt = require( 'bcrypt' ),
	isNil = require( 'lodash/isNil' ),
	get = require( 'lodash/get' ),
	{ merge, isStringLen } = require('./utils')
;

function ApiRest( server, options ){
	const me = this;
	me.server = server;
	
	// const reg_jwt_err_msg = /Invalid credentials|Invalid token|Expired token/i;
	// const reg_jwt_err_msg = /token is null|Invalid token|Expired token/i;
	
	me.options = merge( {
		collection_limit: 20,
		debug: false,
		debug_cleanup: false,
		db_crud: null,
		auth: {
			secret: null,//___ mandatory
			// secret: '!AmazingSecret!',//___ mandatory
			login: {//__ might be null when managed with a real SSO
				path: '/login',
				model_property: 'login'
			},
			findUserWithProp: async function( prop, value, rest ){
				const model = await rest.getModel( 'User', null );
				if( model instanceof Error ) throw me.forgeRequestError( model );
				const user = await model.findOne( { where: { [ prop ]: value } } );
				if( !user ) return user;
				if( rest.options.auth.validateUser ) rest.options.auth.validateUser( user );
				return user.get();
			},
			validateUser( user ){
				// console.log('### validateIser', user );
				if( user.disabled ) throw new Error( 'UserDisabled.' );
				if( user.roles != 'admin' && ('confirmed' in user) && !user.confirmed ) throw new Error( 'InvalidUser' );//'UserNotConfirmed.' );
			},
			forgePayload( user ){
				const res = {
					id: user.id,
					roles: user.roles
					// , login:user.login
				};
				if( user.scope ) res.scope = user.scope;
				return res;
			},
			//__ TODO : remove forgeCrendentials as login is not used in authentication (only on login)
			// , forgeCredentials( payload, user ){
			// 	payload.login = user.login;
			// 	return payload;
			// }
			sign: { algorithm: 'HS256', expiresIn: '24h' },
			strategy( rest, secret ){
				return rest.server.register( require( 'hapi-auth-jwt2' ) )
				.then( function(){
					rest.server.auth.strategy( 'jwt', 'jwt', {
						key: secret,
						verifyOptions: { algorithms: [rest.options.auth.sign.algorithm] },// pick a strong algorithm
						validate: async function( decoded, request, reply ){
							// console.log('>>>>>> validate', decoded );
							let user;
							try{
								user = await rest.options.auth.findUserWithProp( 'id', decoded.id, rest );
							}catch( err ){
								throw me.forgeRequestError( err );
							}
							
							// console.log('>>> user found', user );
							const res = {
								isValid: !!user,
							};
							if( user && rest.options.auth.forgeCredentials ){
								res.credentials = rest.options.auth.forgeCredentials( decoded, user );
							}
							return res;
						},
					} );
					rest.server.auth.default( 'jwt' );
					
				} );
			}
			
		},
		cleanup_result: {
			item_fields: ['name', 'errors', 'fields'],
			err_fields: ['message', 'type', 'path', 'value', 'origin', 'validatorKey', 'validatorName', 'validatorArgs']
		}
	}, options, true );
	
	me.routes_prefix = server.realm.modifiers.route.prefix;
	
	if( !me.options.db_crud ) throw new Error( 'UndefinedDbCrud : options.db_crud must be defined.' );
	
	me.db_crud = new DbCrud( me.options.db_crud );
	
	if( me.options.debug ) console.log( '...new ApiRest', me.options );
}

//___ TODO : implement querystring

Object.assign( ApiRest.prototype, {
	initialize: async function(){//_ promise
		const me = this;
		await me.db_crud.initialize();
		//__ check scopes "collection" & "single" on each models
		for( let key in me.db_crud.database.models ){
			let model = me.db_crud.database.models[ key ];
			if( model.options.through ) continue;
			if( !get( model.options, 'scopes.collection' ) ) throw new Error( 'ModelMissingScope : Model "' + model.name + '" must have a "collection" scope.' );
			if( !get( model.options, 'scopes.single' ) ) throw new Error( 'ModelMissingScope : Model "' + model.name + '" must have a "single" scope .' );
		}
		
		if( me.options.auth ){
			
			if( !isStringLen( me.options.auth.secret, 10 ) ) {
				throw new Error( 'options.auth.secret must be a string with a length >= 10.' );}
			
			if( me.options.auth.strategy ){
				me.options.auth.strategy( me, me.options.auth.secret );
			}
			
			if( me.options.auth.login ){
				//__ login route
				me.server.route( {
					method: ['POST'],
					path: me.options.auth.login.path,
					options: {
						auth: false,
						cors: {
							//_ must add 'Authorization' so js could access this response header ! (sent by login)
							additionalExposedHeaders: ['Authorization'],
							credentials: true,
							//_ WARN cors false just disable hapi handling, for allowing for this route, just allow wildcard
							// origin: ['*'],
						},
					},
					handler: async function( request, reply ){
						
						let err_bad_creds = 'BadCredentials';
						
						let headers = {};
						
						if( !request.payload ) throw me.forgeRequestError( new Error( err_bad_creds ) );
						if( !isStringLen( request.payload.login, 1 ) || !isStringLen( request.payload.password, 1 ) ){
							throw me.forgeRequestError( new Error( err_bad_creds ) );}
						// console.log('--- findUser', request.payload.login);
						let user;
						try{
							user = await me.options.auth.findUserWithProp( me.options.auth.login.model_property, request.payload.login, me );
						}catch( e ){
							throw me.forgeRequestError( e );
						}
						
						if( !user ) throw me.forgeRequestError( new Error( err_bad_creds ) );
						
						if( !isStringLen( user.password, 1 ) ){
							const err = new Error( 'UserMissingFieldPassword : please check user has password, or scope or query attributes.' );
							// console.error( err );
							throw me.forgeRequestError( err );
						}
						
						const valid = await bcrypt.compare( request.payload.password, user.password );
						if( !valid ) throw me.forgeRequestError( new Error( err_bad_creds ) );
						const payload = me.options.auth.forgePayload( user );
						
						headers.Authorization = JsonWebToken.sign( payload, me.options.auth.secret, me.options.auth.sign );
						
						const res = reply.response( payload );
						
						for( let key in headers ){ res.header( key, headers[ key ] );}
						
						return res;
					}
				} );
			}
		}
		
		// __ routes
		me.server.route( {//__ collection
			method: ['GET', 'POST'],
			path: '/{model}',
			options: {
				cors: {
					credentials: true,
				},
			},
			handler: async function( request, reply ){
				// console.log('-- handler Model', request.payload );
				if( (request.response instanceof Error) ) return reply.continue;
				
				let result;
				try{
					switch( request.method.toUpperCase() ){
						case 'POST' ://__ CREATE new record
							// console.log('handle create', request.auth );
							if( request.query.clone ){
								result = await me.db_crud.clone( request.params.model, request.query.clone, {
									properties: request.payload,
									scopes: 'single',
									credentials: request.auth.credentials
								} );
							}else{
								result = await me.db_crud.create( request.params.model, request.payload, {
									credentials: request.auth.credentials
								} );
							}
							result = me.cleanupResult( result );
							const model = await me.db_crud.getModel( request.params.model );
							if( model instanceof Error ) throw me.forgeRequestError( model );
							result = reply.response( result )
							.code( 201 )
							.location( request.path + '/' + result[ model.primaryKeyField ] )
							;
							break;
						case 'GET' ://__ READ collection
							result = await me.db_crud.read( request.params.model, {
								scopes: 'collection',
								limit: me.options.collection_limit,
								credentials: request.auth.credentials
							} )
							;
							result = me.cleanupResult( result );
							break;
					}
				}catch( err ){
					// console.log('# error handle');
					throw me.forgeRequestError( err );
				}
				return result;
			}
		} );
		
		me.server.route( {//__ single
			method: ['GET', 'PATCH', 'PUT', 'DELETE'],
			path: '/{model}/{id}',
			options: {
				cors: {
					credentials: true
				},
			},
			handler: async function( request, reply ){
				if( (request.response instanceof Error) ) return reply.continue;
				// console.log('__ handler single %s', request.method );
				
				let result;
				try{
					switch( request.method.toUpperCase() ){
						case 'GET' ://__ READ single
							result = await me.db_crud.read( request.params.model, {
								scopes: 'single',
								single_key: request.params.id,
								credentials: request.auth.credentials
							} );
							// console.log('>>> record', result );
							if( !result ) throw new Error( 'RecordNotFound.' );
							result = me.cleanupResult( result );
							break;
						case 'PATCH' :
						case 'PUT' ://__ UPDATE single
							result = await me.db_crud.update( request.params.model, {
								[ request.params.id ]: request.payload
							}, {
								// scopes: 'single'
								// single_key: request.params.id,
								credentials: request.auth.credentials
							} );
							// console.log('>>> update result', result );
							result = result[ request.params.id ];
							if( result instanceof Error ) throw result;
							
							// console.log('............. res', res );
							
							if( !result.result ) throw new Error( 'RecordNotFound.' );//__ update count is falsy (0)
							
							result = me.cleanupResult( result );
							break;
						case 'DELETE' ://__ DELETE single
							result = await me.db_crud.delete( request.params.model, {
								// scopes: 'single'
								delete_keys: request.params.id,
								limit: 1,
								credentials: request.auth.credentials
							} );
							if( !result.del_count ) throw new Error( 'RecordNotFound.' );
							result = me.cleanupResult( result );
							// pr = me.delete( request.params.model, request.params.id );
							break;
					}
				}catch( err ){
					throw me.forgeRequestError( err );
				}
				
				return result;
			}
		} );
		
		return me.server.expose( {
			getOption: me.getOption.bind( me ),
			forgePath: me.forgePath.bind( me ),
			cleanupResult: me.cleanupResult.bind( me ),
			setDebugCRUD( b ){ me.db_crud.options.debug = b;},
			dbCRUD(){ return me.db_crud;},
			getRoutesPrefix: () => this.routes_prefix,
		} );
	},
	getOption( path ){ return get( this.options, path );},
	forgePath( model_key, record_key ){
		let res = this.routes_prefix + '/' + model_key;
		if( !isNil( record_key ) ) res += '/' + record_key;
		return res;
	},
	getModel( model_key, scopes ){
		return this.db_crud.getModel( model_key, scopes );
	},
	cleanupResult( result, b ){//__ cleanup error fields from Sequelize for request result
		if( isNil( result ) ) return result;
		
		const is_array = result instanceof Array;
		if( !is_array ) result = [result];
		
		const me = this;
		if( me.options.debug_cleanup ) console.log( '..........cleanupResult' );
		
		result.forEach( function( item, index ){
			if( item.__clean || typeof item != 'object' ) return;
			
			if( me.options.debug_cleanup ) console.log( '.............cleanupResult item', typeof item );
			
			Object.defineProperty( item, '__clean', { value: 1, configurable: true } );
			
			if( item instanceof Error ){
				const rec = {};
				if( me.options.debug_cleanup ) console.log( '.............cleanupResult item is an error', item.name );
				
				// return;
				me.options.cleanup_result.item_fields.forEach( function( item_field ){
					// if( me.options.debug_cleanup )    console.log('.................cleanupResult item error field', item_field );
					switch( item_field ){
						case 'name':
							rec.error = item[ item_field ];
							delete item[ item_field ];
							break;
						case 'errors':
							rec.errors = [];
							if( item.errors ){
								item.errors.forEach( function( err, index ){
									rec.errors[ index ] = {};
									me.options.cleanup_result.err_fields.forEach( function( err_field ){
										// if( me.options.debug_cleanup )    console.log('....................cleanupResult item error sub field', err_field );
										rec.errors[ index ][ err_field ] = err[ err_field ];
									} );
								} );
							}
							break;
						default:
							rec[ item_field ] = item[ item_field ];
							break;
					}
				} );
				
				result[ index ] = rec;
			}else{
				if( typeof item.get == 'function' ){
					item = item.get();
					if( me.options.debug_cleanup ) console.log( '..............cleanupResult get is a function', Object.keys( item ) );
					Object.defineProperty( item, '__clean', { value: 1, configurable: true } );
					result[ index ] = item;
				}else{
					// if( b ) console.log('- item', Object.keys( item ), item );
					
					// let stack = 10;
					for( let key in item ){
						// if(--stack < 0) break;
						if( typeof item[ key ] != 'object' ) continue;
						if( me.options.debug_cleanup ) console.log( '....sub clean', key );
						item[ key ] = me.cleanupResult( item[ key ] );
					}
				}
				
				
			}
			
			delete item.__clean;
			
			
		} );
		if( me.options.debug_cleanup ) console.log( '........../ cleanupResult end' );
		return is_array ? result : result[ 0 ];
		
	},
	forgeRequestError( _err ){
		let err = _err;
		// console.log('>>> forgeRequestError', err );
		// if( typeof err === 'string' )   err = new Error( err );
		if( this.options.debug ) console.warn( '...request error :', err );
		// if( !err.isBoom ){
		if( err.name ){
			const match = err.name.match( /sequelize([^ ]*)/i );
			if( match ){
				// console.log('### err sequelize', match );
				const msg = err.toString();
				err = this.cleanupResult( err );
				const serr = (err.isBoom || match[ 1 ].toLowerCase() == 'scopeerror') ? err : Boom.badData( err );
				serr.output.payload.message = msg;
				// console.log('___ serr', typeof err.message );
				if( err.errors ) serr.output.payload.errors = err.errors;
				err = serr;
				return err;
			}
		}
		
		if( !err.isBoom ){
			const match = err.message.match( /UnknownModel|RecordNotFound|CloneSrcNotFound|UndefinedProperties|BadCredentials|MissingCredentials|InvalidToken|ExpiredToken|CredentialsMissingProperty|Unauthorized|UserDisabled|InvalidUser|UserNotConfirmed/ );
			// if( this.options.debug ) console.warn('...request match error', match, match[0] );
			// console.log('### match err', match[0]);
			if( match ){
				switch( match[ 0 ] ){
					case 'UnknownModel' :
					case 'RecordNotFound' :
					case 'CloneSrcNotFound' :
						err = Boom.notFound( err );
						break;
					case 'BadCredentials':
					case 'MissingCredentials':
					case 'Unauthorized':
					case 'InvalidToken':
					case 'ExpiredToken':
						err = Boom.unauthorized( err );
						break;
					case 'UserDisabled':
					case 'UserNotConfirmed':
					case 'InvalidUser':
						err = Boom.forbidden( err );
						break;
					case 'UndefinedProperties':
					case 'CredentialsMissingProperty' :
						err = Boom.badData( err );
						break;
				}
			}
		}
		// }
		return err;
	}
} );

module.exports = {
	pkg: require( '../package.json' ),
	register: function( server, options ){
		return new ApiRest( server, options )
		.initialize()
			;
	}
};
