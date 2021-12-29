const isString = require( 'lodash/isString' ),
	deepMerge = require( 'deepmerge' ),
	deepMergeOptions = { arrayMerge: ( destinationArray, sourceArray, options ) => sourceArray }
;

module.exports = {
	merge: ( target, source ) => {
		return deepMerge( target, source, deepMergeOptions );
	},
	isStringLen: ( value, len ) => {
		if( !isString( value ) ){ return false;}
		return isNaN( len ) ? true : value.length >= len;
	}
};
