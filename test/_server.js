const Hapi = require( '@hapi/hapi' ),
	Path = require( 'path' ),
	isNaN = require( 'lodash/isNaN' ),
	{ merge, isStringLen } = require('../src/utils')
	;

module.exports = async function( options ){
	
	options = merge( {
		server: {
			host: 'localhost',
			port: process.env.port || 3000,
			routes: {
				cors: {
					origin: [
						'http://client-ihm.org',
						'chrome-search://local-ntp',//__ special google devtools origin
					],
					// credentials: true,
				}
			}
		},
		start: false,
		plugins: {
			'api-rest': {//
				plugin: require( Path.join( __dirname, '../src/index' ) ),
				routes: {
					prefix: '/api'
				},
				options: {
					debug: true,
					debug_cleanup: false,
					db_crud: {
						dir_models: Path.join( __dirname, 'models' ),
						models: {
							User: {
								sync: { force: true },
								roles: {
									admin: 1,
									user: { read: 'owner' }
								},
								mock: function( model ){
									return model.bulkCreate( [
										{ login: 'admin@domain.org', password: 'demo', roles: 'admin' },
										{ login: 'user1@domain.org', password: 'demo', roles: 'user', confirmed: 1 },
										{ login: 'user2@domain.org', password: 'demo', roles: 'user', confirmed: 1, disabled: 1 },
										{ login: 'user3@domain.org', password: 'demo', roles: 'user' },
										{ login: 'user4@domain.org', password: 'demo', roles: 'manager', confirmed: 1 }
									] )
									;
								}
							},
							Task: {
								sync: { force: true },
								// disabled:1,
								roles: {
									admin: 1,
									// , user: {
									// 	// create:
									// }
									manager: {
										create: 1,
										read: 1,
										update(){
											return {
												fields: ['title'],
												owner: true
											};
										},
										delete: 1
									},
									user: {
										create: function(){
											return {};
										},
										read: 'owner', update: 'owner', delete: 'owner'
									}
								},
								mock: function( model ){
									return model.bulkCreate( [
										{ title: 'Task 1', content: 'Content Task 1 owned by user 1', user_id: 1 },
										{ title: 'Task 2', content: 'Content Task 2 owned by user 2', user_id: 2 },
										{ title: 'Task 3', content: 'Content Task 3 owned by user 3', user_id: 3 },
										{ title: 'Task 4', content: 'Content Task 4 owned by user 4', user_id: 4 },
										{ title: 'Task 5', content: 'Content Task 5 owned by user 5', user_id: 5 }
									] )
									;
								}
							}
						},
						onModels: function( models, Sequelize, plugin ){
							//__ good place for associations ( after all models loaded but before sync )
							// console.log( '...onModels', models, plugin );
							models.Task.hasMany( models.Task, { as: 'children', foreignKey: 'parent' } );
							// if( models.User ){
							// 	models.User.hasMany( models.Task, { foreignKey: 'user_id', as: 'tasks' } );
							// }
						}
					}
				}
			}
		},
		register_options: {},
		stackTraceLimit: null,
	}, options, true );
	// console.log('...proto', options.plugins['api-rest'].options.db_crud );
	// console.log('...creating server', options );

	if( !isNaN( options.stackTraceLimit ) ){
		Error.stackTraceLimit = options.stackTraceLimit;}
	
	const server = new Hapi.Server( options.server );
	
	for( let key in options.plugins ){
		await server.register( options.plugins[ key ] );
		if( options.plugins[ key ].onRegistered ) options.plugins[ key ].onRegistered( server );
		console.log( '- plugin registered', key );
	}
	
	if( options.start ) await server.start();
	else await server.initialize();
	
	//__ must emit each request manually ( by default only internal or errors )
	server.ext( 'onRequest', function( request, h, err ){
		server.log( ['request'], request );
		return h.continue;
	} );
	
	server.events.on( {
		name: 'log',
		channels: 'app',
		filter: ['request']/*, filter:'received'*/
	}, function( { data: request }/*, tags*/ ){
		// console.log('___request:', event );
		console.log( '___request:', request.method.toUpperCase(), request.path );//, request.route.settings );//, request.route.settings );
		// console.log('      headers:', request.auth, request.headers );
	} );
	
	console.log( '.......server running', server.info, server.plugins );
	return server;
	
};

if( require.main === module ){
	module.exports( {
		start: true,
		plugins: {
			'api-rest': {
				options: {
					auth: {
						secret: '!AmazingSecret!'
					}
				}
			}
		},
	} );
}
