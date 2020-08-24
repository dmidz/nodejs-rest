const isString = require( 'lodash/isString' ),
	isArray = require( 'lodash/isArray' ),
	mergeWith = require( 'lodash/mergeWith' ),
	replaceIfArray = ( to, from ) => (isArray( to ) ? from : undefined)
;

module.exports = {
	merge: ( ...args ) => mergeWith( ...args, replaceIfArray ),
	isStringLen: ( value, len ) => {
		if( !isString( value ) ){ return false;}
		return isNaN( len ) ? true : value.length >= len;
	}
};
