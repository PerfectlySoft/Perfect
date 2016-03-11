//
//  GameState.swift
//  Ultimate Noughts and Crosses
//
//  Created by Kyle Jessup on 2015-10-28.
//  Copyright © 2015 PerfectlySoft. All rights reserved.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

// X,Y
// Across, Down
//  _________________
// | 0,0 | 1,0 | 2,0 |
// | 0,1 | 1,1 | 2,1 |
// | 0,2 | 1,2 | 2,2 |
//  -----------------


let INVALID_ID = -1

let MAX_X = 8
let MAX_Y = 8

enum PieceType: Int {
	case None = 0, Oh = 1, Ex = 2, OhWin = 3, ExWin = 4
}

class Player {
	let nick: String
	let gameId: Int
	let type: PieceType
	init(nick: String, gameId: Int, type: PieceType) {
		self.nick = nick
		self.gameId = gameId
		self.type = type
	}
}

class Board: CustomStringConvertible {
	typealias IndexType = (Int, Int)
	
	var slots: [[PieceType]] = [[.None, .None, .None], [.None, .None, .None], [.None, .None, .None]]
	
	var owner: PieceType = .None
	
	init() {}
	
	subscript(index: IndexType) -> PieceType {
		get {
			return self.slots[index.0][index.1]
		}
		set(newValue) {
			self.slots[index.0][index.1] = newValue
		}
	}
	
	var description: String {
		var s = ""
		
		for y in 0..<3 {
			if y != 0 {
				s.appendContentsOf("\n")
			}
			for x in 0..<3 {
				let curr = self[(x, y)]
				switch curr {
				case .Ex:
					s.appendContentsOf("X")
				case .Oh:
					s.appendContentsOf("O")
				default:
					s.appendContentsOf("_")
				}
			}
		}
		return s
	}
}

class Field: CustomStringConvertible {
	typealias IndexType = (Int, Int)
	
	var boards: [[Board]] = [[Board(), Board(), Board()], [Board(), Board(), Board()], [Board(), Board(), Board()]]
	
	init() {}
	
	subscript(index: IndexType) -> Board {
		get {
			return self.boards[index.0][index.1]
		}
		set(newValue) {
			self.boards[index.0][index.1] = newValue
		}
	}
	
	var description: String {
		var s = ""
		
		for y in 0..<3 {
			if y != 0 {
				s.appendContentsOf("\n\n")
			}
			let b0 = self[(0, y)].description.characters.split("\n")
			let b1 = self[(1, y)].description.characters.split("\n")
			let b2 = self[(2, y)].description.characters.split("\n")
			for x in 0..<3 {
				if x != 0 {
					s.appendContentsOf("\n")
				}
				s.appendContentsOf(b0[x])
				s.appendContentsOf(" ")
				s.appendContentsOf(b1[x])
				s.appendContentsOf(" ")
				s.appendContentsOf(b2[x])
			}
		}
		return s
	}
}

class GameState {
	
}


