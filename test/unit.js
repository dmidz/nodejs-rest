const Lab = require( '@hapi/lab' ),
	lab = exports.lab = Lab.script(),
	{ expect } = require( '@hapi/code' ),
	JsonWebToken = require( 'jsonwebtoken' ),
	Server = require( './_server' )
;

lab.experiment( '//__ TEST @dmidz/rest', function(){
	
	let server = null;
	let plugin_rest = null;
	
	const collection_limit = 10;
	
	const options = {
		stackTraceLimit: 3,
		plugins: {
			'api-rest': {
				options: {
					collection_limit: collection_limit,
					//debug: true,
					auth: {
						secret: '!AmazingSecret2!'
					}
				}
			}
		},
	};
	
	lab.before( async function(){
		server = await Server( options );
		plugin_rest = server.plugins[ 'rest' ];
		// console.log('plugins', server.plugins );
	} );
	
	let token = null;
	let token_manager = null;
	
	lab.test( 'getOption( path ) should return the corresponding options path value.', () => {
		expect( plugin_rest.getOption( 'collection_limit' ) ).to.equal( collection_limit );
	} );
	
	lab.test( 'forgePath( model_key, record_key? ) should return a string url path.', () => {
		let path = plugin_rest.forgePath( 'Task' );
		const prefix = plugin_rest.getRoutesPrefix();
		expect( path ).to.equal( prefix + '/Task' );
		path = plugin_rest.forgePath( 'Task', 3 );
		expect( path ).to.equal( prefix + '/Task/3' );
	} );
	
	lab.test( '/login request with RIGHT CREDENTIALS should return a 200 with token JWT in authorization header.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'login' ),
			payload: { login: 'user1@domain.org', password: 'demo' },
		} )
		// console.log( '# res login', res.result/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 200 );
		expect( res.headers.authorization ).to.be.a.string();
		token = res.headers.authorization;
		token_manager = JsonWebToken.sign( { id: 5, roles: 'manager' }
			, plugin_rest.getOption( 'auth.secret' ), plugin_rest.getOption( 'auth.sign' ) );
	} );
	
	lab.test( '/login request with NO CREDENTIALS should return a 401 BadCredentials.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'login' ), payload: {}
		} );
		// console.log('# res', res.result );
		expect( res.statusCode ).to.equal( 401 );
		expect( res.result.message ).to.match( /BadCredentials/ );
	} );
	
	lab.test( '/login request with BAD LOGIN should return a 401 BadCredentials.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'login' )
			, payload: { login: 'bad_login', password: 'zzz' }
		} );
		// console.log('# res login', res.result, res.headers );
		expect( res.statusCode ).to.equal( 401 );
		expect( res.result.message ).to.match( /BadCredentials/ );
	} );
	
	lab.test( '/login request with BAD PASSWORD should return a 401 BadCredentials.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'login' )
			, payload: { login: 'user1@domain.org', password: 'zzz' }
		} );
		// console.log('# res login', res.result, res.headers );
		expect( res.statusCode ).to.equal( 401 );
		expect( res.result.message ).to.match( /BadCredentials/ );
	} );
	
	lab.test( '/login request with RIGHT CREDENTIALS of a DISABLED user should return a 403 UserDisabled.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'login' )
			, payload: { login: 'user2@domain.org', password: 'demo' }
		} );
		// console.log('# res login', res.result, res.headers );
		expect( res.statusCode ).to.equal( 403 );
		expect( res.result.message ).to.match( /UserDisabled/ );
	} );
	
	lab.test( '/login request with RIGHT CREDENTIALS of a NOT CONFIRMED user should return a 403 InvalidUser.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'login' )
			, payload: { login: 'user3@domain.org', password: 'demo' }
		} );
		// console.log('# res login', res.result, res.headers );
		expect( res.statusCode ).to.equal( 403 );
		expect( res.result.message ).to.match( /InvalidUser/ );
	} );
	
	lab.test( 'create POST /Task with right JWT credentials should return a 201 with location of created record.', async () => {
		// console.log('_TEST', token );
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'Task' ),
			headers: {
				authorization: token,
			},
			payload: {
				title: 'Hello new task !',
				content: 'Wonderful content.'
			}
		} );
		// console.log( '# res :', res.result, res.headers );
		expect( res.statusCode ).to.equal( 201 );
		expect( res.result ).to.be.an.object();
		expect( res.result.title ).to.equal( 'Hello new task !' );
		expect( res.headers.location ).to.equal( plugin_rest.forgePath( 'Task', res.result.id ) );
	} );
	
	lab.test( 'create POST /Task with query "clone" should return a 201 with cloned record.', async () => {
		// plugin_rest.setDebugCRUD( true );
		const clone_props = { title: 'Hello cloned task.' };
		const res = await server.inject( {
			method: 'POST',
			url: plugin_rest.forgePath( 'Task' ) + '?clone=6',
			headers: { authorization: token },
			payload: clone_props
		} );
		// console.log('# res :', res.payload, res.result /*, res.headers*/ );
		expect( res.statusCode ).to.equal( 201 );
		expect( res.result ).to.be.an.object();
		expect( res.result.title ).to.equal( clone_props.title );
		expect( res.result.content ).to.equal( 'Wonderful content.' );
		expect( res.headers.location ).to.equal( plugin_rest.forgePath( 'Task', res.result.id ) );
		// plugin_rest.setDebugCRUD( false );
	} );
	
	lab.test( 'create POST /Task with missing JWT credentials should return a 401 BadCredentials.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'Task' ),
			payload: {
				title: 'Hello new task 2 !',
				content: 'Wonderful content.'
			}
		} );
		// console.log('# res :', res.result, res.result/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 401 );
	} );
	
	lab.test( 'create POST /Task with invalid JWT creds should return a 401 Unauthorized.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'Task' ),
			payload: {
				title: 'Hello new task 2 !',
				content: 'Wonderful content.'
			},
			headers: { authorization: token + 'zzzz' },
		} );
		// console.log('# res :', res.result/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 401 );
	} );
	
	lab.test( 'create POST /Task with valid JWT of unknown user should return a 401 Unauthorized.', async () => {
		const token_unknown = JsonWebToken.sign( { id: 99, roles: 'manager' },
			plugin_rest.getOption( 'auth.secret' ), plugin_rest.getOption( 'auth.sign' ) );
		
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'Task' ),
			payload: { title: 'Hello new task 2 !', content: 'Wonderfull content.' },
			headers: { authorization: token_unknown },
		} );
		// console.log('# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 401 );
	} );
	
	lab.test( 'create POST /Task with expired JWT creds should return a 401 Unauthorized.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'Task' ),
			payload: {
				title: 'Hello new task 2 !',
				content: 'Wonderful content.'
			},
			headers: {
				//__ forge an expired token : 30 hours (expiry is 24)
				authorization: JsonWebToken.sign( { id: 2, roles: 'user', iat: Math.floor( Date.now() / 1000 ) - 3600 * 30 },
					plugin_rest.getOption( 'auth.secret' ), plugin_rest.getOption( 'auth.sign' ) )
			}
		} );
		// console.log('# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 401 );
	} );
	
	lab.test( 'create POST /Task with no payload should return a 422 UndefinedProperties.', async () => {
		const res = await server.inject( { method: 'POST', url: plugin_rest.forgePath( 'Task' ), headers: { authorization: token } } );
		// console.log('# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 422 );
	} );
	
	lab.test( 'create POST /Task with Sequelize error should throw a 422 BadRequest with comprehensive but cleaned up error result.', async () => {
		const res = await server.inject( {
			method: 'POST', url: plugin_rest.forgePath( 'Task' ), headers: { authorization: token },
			payload: {
				title: null,//__ this should throw a NotNull constraint violation
				content: 'Wonderful content.'
			}
		} );
		// console.log('# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 422 );
	} );
	
	lab.test( 'read GET /Tasks should return a 200 with a array of record, having no content field as the collection scope.', async () => {
		const res = await server.inject( { method: 'GET', url: plugin_rest.forgePath( 'Task' ), headers: { authorization: token } } );
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 200 );
		expect( res.result ).to.be.an.array();
		expect( res.result.length ).to.be.at.least( 1 );
		expect( res.result[ 0 ] ).to.be.an.object();
		//__ because content field is not included in the scope "collection"
		expect( res.result[ 0 ].content ).to.be.undefined();
	} );
	
	lab.test( 'read GET /SomeUnknownModel should return a 404 UnknownModel.', async () => {
		const res = await server.inject( {
			method: 'GET',
			url: plugin_rest.forgePath( 'SomeUnknownModel' ),
			headers: { authorization: token }
		} );
		// console.log( '# res :', res.result/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 404 );
	} );
	
	lab.test( 'read GET /Task/{id} should return a 200 with a record.', async () => {
		const res = await server.inject( {
			method: 'GET',
			url: plugin_rest.forgePath( 'Task', 2 ),
			headers: { authorization: token }
		} );
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 200 );
		expect( res.result ).to.be.an.object();
		expect( res.result.id ).to.equal( 2 );
	} );
	
	lab.test( 'read GET /Task/{id} with not owner credentials should return a 404.', async () => {
		const res = await server.inject( {
			method: 'GET',
			url: plugin_rest.forgePath( 'Task', 1 ),
			headers: { authorization: token }
		} );
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 404 );
		expect( res.result.message ).to.match( /RecordNotFound/ );
	} );
	
	lab.test( 'read GET /Task/SomeUnknownKey should return a 404 with RecordNotFound', async () => {
		const res = await server.inject( {
			method: 'GET',
			url: plugin_rest.forgePath( 'Task', 'SomeUnknownKey' ),
			headers: { authorization: token }
		} );
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 404 );
		expect( res.result.message ).to.match( /RecordNotFound/ );
	} );
	
	lab.test( 'update PATCH /Task/{id} should return a 200 and then request it should return modified values.', async () => {
		const changes = {
			title: 'Title modified !'
			, content: 'Content modified.'
		};
		const res = await server.inject( {
			method: 'PATCH', url: plugin_rest.forgePath( 'Task', 2 )
			, payload: changes, headers: { authorization: token }
		} );
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 200 );
		expect( res.result ).to.equal( 1 );
		
		const read = await server.inject( {
			method: 'GET',
			url: plugin_rest.forgePath( 'Task', 2 ),
			headers: { authorization: token }
		} );

		expect( read.result ).to.be.an.object();
		expect( read.result.title ).to.equal( changes.title );
		expect( read.result.content ).to.equal( changes.content );
	} );
	
	lab.test( 'update PATCH /Task/{id} invalid property should return a 422.', async () => {
		const changes = { title: null };
		const res = await server.inject( {
			method: 'PATCH',
			url: plugin_rest.forgePath( 'Task', 2 ),
			headers: { authorization: token },
			payload: changes,
		} );
		// console.log( '### res :', res.result/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 422 );
	} );
	
	lab.test( 'update PATCH /Task/{id} with user rights restricted fields should return a 200 and restricted fields not modified.', async () => {
		const changes = { title: 'Title modified !', content: 'Content modified.' };
		const res = await server.inject( {
			method: 'PATCH', url: plugin_rest.forgePath( 'Task', 5 )
			, payload: changes, headers: { authorization: token_manager }
		} );

		// console.log( '# res update :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 200 );
		expect( res.result ).to.equal( 1 );
		
		const read = await server.inject( {
			method: 'GET',
			url: plugin_rest.forgePath( 'Task', 5 ),
			headers: { authorization: token_manager }
		} );

		// console.log( '# res get :', read.payload/*, res.headers*/ );
		expect( read.result ).to.be.an.object();
		expect( read.result.title ).to.equal( changes.title );
		expect( read.result.content ).to.not.equal( changes.content );
	} );
	
	lab.test( 'update PATCH /Task/{id} with user rights restricted fields and owner restriction should return a 404 for a non owned record.', async () => {
		const changes = { title: 'Title modified !', content: 'Content modified.' };
		const res = await server.inject( {
			method: 'PATCH', url: plugin_rest.forgePath( 'Task', 3 )
			, payload: changes, headers: { authorization: token_manager }
		} );

		// console.log( '# res update :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 404 );
	} );
	
	lab.test( 'update PATCH /Task/{id} with NO payload should return a 422 UndefinedProperties.', async () => {
		const res = await server.inject( {
			method: 'PATCH',
			url: plugin_rest.forgePath( 'Task', 2 ),
			headers: { authorization: token },
			// payload: { title: null },
		} )
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 422 );
		expect( res.result.message ).to.match( /UndefinedProperties/ );
	} );
	
	lab.test( 'update PATCH /Task/{id} with UNKOWN ID should return a 404 RecordNotFound.', async () => {
		const res = await server.inject( {
			method: 'PATCH', url: plugin_rest.forgePath( 'Task', 'SomeUnknownKey' )
			, payload: { title: 'Title modified !', content: 'Content modified.' }, headers: { authorization: token }
		} );
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 404 );
		expect( res.result.message ).to.match( /RecordNotFound/ );
	} );
	
	lab.test( 'delete DELETE /Task/{id} with UNKNOWN ID should return a 404 RecordNotFound.', async () => {
		const res = await server.inject( {
			method: 'DELETE',
			url: plugin_rest.forgePath( 'Task', 'SomeUnknownKey' ),
			headers: { authorization: token }
		} );
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 404 );
		expect( res.result.message ).to.match( /RecordNotFound/ );
	} );
	
	lab.test( 'delete DELETE /Task/{id} with KNOWN ID should return a 200 with deleted count, then read it should return a 404.', async () => {
		const res = await server.inject( {
			method: 'DELETE',
			url: plugin_rest.forgePath( 'Task', 2 ),
			headers: { authorization: token }
		} );
		// console.log( '# res :', res.payload/*, res.headers*/ );
		expect( res.statusCode ).to.equal( 200 );
		expect( res.result.del_count ).to.equal( 1 );

		//__ try to get it again
		const read = await server.inject( {
			method: 'GET',
			url: plugin_rest.forgePath( 'Task', 1 ),
			headers: { authorization: token }
		} );

		expect( read.statusCode ).to.equal( 404 );
	} );
	
} );
