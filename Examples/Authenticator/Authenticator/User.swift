//
//  User.swift
//  Authenticator
//
//  Created by Kyle Jessup on 2015-11-09.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.
//
//     You should have received a copy of the GNU Affero General Public License
//     along with this program.  If not, see <http://www.gnu.org/licenses/>.
//


class User {
	
	let id: Int
	let firstName: String
	let lastName: String
	let email: String
	let authKey: String
	
	init(id: Int, first: String, last: String, email: String, authKey: String) {
		self.id = id
		self.firstName = first
		self.lastName = last
		self.email = email
		self.authKey = authKey
	}
}
